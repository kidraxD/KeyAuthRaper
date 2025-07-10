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

	std::string name, ownerid, version, url, path;
	static bool debug;

	api(std::string name, std::string ownerid, std::string version, std::string url, std::string path, bool debugParameter = false)
		: name(name), ownerid(ownerid), version(version), url(url), path(path)
	{
		setDebug(debugParameter);
	}

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
		std::string downloadLink;
	};

	class responsedata {
	public:
		// response data
		std::vector<channel_struct> channeldata;
		bool success{};
		std::string message;
		bool isPaid{};
	};

	bool activate = false;
	class Tfa {
	public:
		std::string secret;
		std::string link;
	private:
	};

	userdata user_data;
	appdata app_data;
	responsedata response;
	Tfa tfa;

private:
	std::string sessionid, enckey;
	static void setDebug(bool value);
};