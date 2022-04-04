use std::{
	io::Read,
	time::{SystemTime, UNIX_EPOCH},
};
use ras_service::{
	*,
	ras_auth_client::{
		get_public_key_for_token,
		RasAuthClient,
	},
};
use serde::{Deserialize};

struct RasChat {
 public_key_for_token: PKey<Public>,
 life_time_token: u128,
 queue: Mutex<Queue>,
 right_role: u8
}

impl RasChat {
	async fn new(config: RasChatConfig) -> RasChat {
		RasChat {
			public_key_for_token: get_public_key_for_token(
				config.login,
				config.password,
				config.ras_auth_uri
			).await,
			life_time_token: config.life_time_token,
			queue: Mutex::new(Queue::new(config.queue_len, config.max_message_len)),
			right_role: config.right_role,
		}
	}
}

impl RasAuthClient for RasChat {
	fn get_verifier(&self) -> Result<Verifier<'_>, ErrorStack> {
		Verifier::new(MessageDigest::sha256(), &self.public_key_for_token)
	}
	fn get_life_time_token(&self) -> u128 {
		self.life_time_token
	}
}

#[derive(Deserialize)]
struct RasChatConfig {
	socket_url: String,
	life_time_token: u128,
	login: String,
	password: String,
	ras_auth_uri: String,
	threads: usize,
	queue_len: usize,
	max_message_len: usize,
	right_role: u8
}

#[derive(Clone)]
struct Message {
	key: String,
	data: String,
}

struct Queue {
	messages: Vec<Message>,
	output_capacity: usize,
	max_message_len: usize,
	end_index: usize,
}

impl Queue {
	fn new(len: usize, max_message_len: usize) -> Queue {
		//max_message_len - max bytes in 1 message
		let messages: Vec<Message> = vec![
			Message {
				key: "".to_string(), data: "".to_string()
			};
			len
		];
		let output_capacity = len * max_message_len;
		let end_index = 0;
		Queue {
			messages,
			output_capacity,
			max_message_len,
			end_index
		}
	}

	fn push(&mut self, key: String, message: String) -> Result<(), ()> {
		if message.len() >= self.max_message_len {
			return Err(());
		}
		self.end_index += 1;
		if self.end_index >= self.messages.len() {
			self.end_index = 0 as usize;
		}
		self.messages[self.end_index] = Message {
			key,
			data: message
		};
		return Ok(())
	}

	fn get_all(&self) -> String {
		let mut result = String::with_capacity(self.output_capacity);
		result += "[\r\n";
		let mut index = (self.end_index + 1) % self.messages.len();
		loop {
			result = result +
				"\"" + &self.messages[index].key + "\":\"" +
				&self.messages[index].data +"\""
			;
			index = (index + 1) % self.messages.len();
			if index == self.end_index + 1 {
				break;
			} else {
				result += ",\r\n";
			}
		}
		result += "]";
		result
	}

	fn get_from(&self, key: &str) -> String {
		let mut result = String::with_capacity(self.output_capacity);
		result += "[\r\n";
		let mut index = (self.end_index + 1) % self.messages.len();
		let mut start_write = false;
		//TODO: Skip empty strings
		loop {
			if start_write {
				result = result +
					"\"" + &self.messages[index].key + "\":\"" +
					&self.messages[index].data +"\""
				;
			}
			index = (index + 1) % self.messages.len();
			if index == self.end_index + 1 {
				break;
			} else if start_write {
				result += ",\r\n";
			}
			if key == &self.messages[index].key {
				start_write = true;
			}
		}
		result += "]";
		result
	}
}

fn ping(
	_runtime: Handle,
	_self_service: Arc<RasChat>,
	_params: Option<&str>)
-> RasResult {
	RasResult::Sync(
		HttpStatus::OK,
		Some("pong".to_string())
	)
}

fn set_message(
	_runtime: Handle,
	self_service: Arc<RasChat>,
	query: Option<&str>)
-> RasResult {
	let query: HashMap<String, Option<String>> = if let Some(query_str) = query {
		match serde_json::from_str(query_str) {
			Ok(query) => query,
			Err(err) => {
				eprintln!("Error! Bad json format: {:?}", err);
				return RasResult::Sync(HttpStatus::BadRequest, None);
			}
		}
	} else {
		return RasResult::Sync(HttpStatus::BadRequest, None);
	};
	let token = match query["token"].as_ref() {
		Some(token) => token,
		None => return RasResult::Sync(HttpStatus::BadRequest, None),
	};
	let token = match self_service.check_and_get_access_token(&token) {
		Ok(token) => token,
		Err(_) => return RasResult::Sync(HttpStatus::AuthenticationTimeout, None),
	};
	if self_service.right_role & token.user_role == 0 {
		return RasResult::Sync(HttpStatus::Forbidden, None);
	}
	let key =  format!(
		"{}{}",
		token.user_name,
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or(std::time::Duration::ZERO)
			.as_millis()
	);
	let message = match &query["message"] {
		Some(message) => message,
		None => return RasResult::Sync(HttpStatus::BadRequest, None),
	};
	{
		let mut queue = match self_service.queue.lock() {
			Ok(queue) => queue,
			Err(err) => {
				eprintln!("Error! queue unreachable: {:?}", err);
				return RasResult::Sync(HttpStatus::InternalServerError, None);
			}
		};
		//TODO: get message without allocation
		match (*queue).push(key, message.to_string()) {
			Ok(_) => return RasResult::Sync(HttpStatus::OK, None),
			Err(_) => RasResult::Sync(HttpStatus::BadRequest, None),
		}
	}
}

fn get_messages(
	_runtime: Handle,
	self_service: Arc<RasChat>,
	query: Option<&str>)
-> RasResult {
	let query: HashMap<String, Option<String>> = if let Some(query_str) = query {
		match serde_json::from_str(query_str) {
			Ok(query) => query,
			Err(err) => {
				eprintln!("Error! Bad json format: {:?}", err);
				return RasResult::Sync(HttpStatus::BadRequest, None);
			}
		}
	} else {
		return RasResult::Sync(HttpStatus::BadRequest, None);
	};
	let token = match query["token"].as_ref() {
		Some(token) => token,
		None => return RasResult::Sync(HttpStatus::BadRequest, None),
	};
	let token = match self_service.check_and_get_access_token(&token) {
		Ok(token) => token,
		Err(_) => return RasResult::Sync(HttpStatus::AuthenticationTimeout, None),
	};
	if self_service.right_role & token.user_role == 0 {
		return RasResult::Sync(HttpStatus::Forbidden, None);
	}
	//TODO: get data without lock
	{
		let queue = match self_service.queue.lock() {
			Ok(queue) => queue,
			Err(err) => {
				eprintln!("Error! queue unreachable: {:?}", err);
				return RasResult::Sync(HttpStatus::InternalServerError, None);
			}
		};
		//TODO: get message without allocation
		return RasResult::Sync(HttpStatus::OK, Some((*queue).get_all()));
	}
}

fn get_messages_from(
	_runtime: Handle,
	self_service: Arc<RasChat>,
	query: Option<&str>)
-> RasResult {
	let query: HashMap<String, Option<String>> = if let Some(query_str) = query {
		match serde_json::from_str(query_str) {
			Ok(query) => query,
			Err(err) => {
				eprintln!("Error! Bad json format: {:?}", err);
				return RasResult::Sync(HttpStatus::BadRequest, None);
			}
		}
	} else {
		return RasResult::Sync(HttpStatus::BadRequest, None);
	};
	let token = match query["token"].as_ref() {
		Some(token) => token,
		None => return RasResult::Sync(HttpStatus::BadRequest, None),
	};
	let token = match self_service.check_and_get_access_token(&token) {
		Ok(token) => token,
		Err(_) => return RasResult::Sync(HttpStatus::AuthenticationTimeout, None),
	};
	if self_service.right_role & token.user_role == 0 {
		return RasResult::Sync(HttpStatus::Forbidden, None);
	}
	let key = match query["start_key"].as_ref() {
		Some(key) => key,
		None => return RasResult::Sync(HttpStatus::BadRequest, None),
	};
	//TODO: get data without lock
	{
		let queue = match self_service.queue.lock() {
			Ok(queue) => queue,
			Err(err) => {
				eprintln!("Error! queue unreachable: {:?}", err);
				return RasResult::Sync(HttpStatus::InternalServerError, None);
			}
		};
		//TODO: get message without allocation
		return RasResult::Sync(HttpStatus::OK, Some((*queue).get_from(key)));
	}
}

fn main() {
	let mut config = String::new();
	{
		std::fs::File::open("config.json")
			.unwrap()
			.read_to_string(&mut config)
			.unwrap();
	}
	let config: RasChatConfig = serde_json::from_str(&config).unwrap();
	let socket_url = config.socket_url.clone();
	let runtime = RasServiceBuilder::<RasChat>::get_runtime(config.threads);
	let service = runtime.block_on(async move {RasChat::new(config).await});
	RasServiceBuilder::new(runtime, service)
		.set_socket_url(&socket_url)
		.add_get_function("ping".to_string(), ping)
		.add_post_function("set_message".to_string(), set_message)
		.add_post_function("get_messages".to_string(), get_messages)
		.add_post_function("get_messages_from".to_string(), get_messages_from)
		.run();
}
