# ras-chat
Microservice for chat

set_message
POST
{
	"token": "some_access_token",
	"message": "some_message"
}

get_messages
POST
{
	"token": "some_access_token"
}

get_messages_from
POST
{
	"token": "some_access_token",
	"start_key": "message_key"
}

TODO:
- Finish TODO-list from code.
- Write tests.
- Write documentation.
