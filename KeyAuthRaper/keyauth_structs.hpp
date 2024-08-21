#pragma once

#include <string>

struct channel_struct
{
	std::string author;
	std::string message;
	std::string timestamp;
};

class api {
public:

	std::string name, ownerid, secret, version, url, path;

	class subscriptions_class {
	public:
		std::string name;
		std::string expiry;
	};

	class userdata {
	public:

		// user data
		std::string username;
		std::string ip;
		std::string hwid;
		std::string createdate;
		std::string lastlogin;

		std::vector<subscriptions_class> subscriptions;
	};

	class appdata {
	public:
		// app data
		std::string numUsers;
		std::string numOnlineUsers;
		std::string numKeys;
		std::string version;
		std::string customerPanelLink;
	};

	class responsedata {
	public:
		// response data
		std::vector<channel_struct> channeldata;
		bool success{};
		std::string message;
	};

	userdata user_data;
	appdata app_data;
	responsedata response;

private:
	std::string sessionid, enckey;
};