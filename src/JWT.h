/*
 Name:		JWT.h
 Created:	8/23/2024 8:35:44 PM
 Author:	zhuji
 Editor:	http://www.visualmicro.com
*/

#ifndef _JWT_h
#define _JWT_h

#if defined(ARDUINO) && ARDUINO >= 100
#include "arduino.h"
#else
#include "WProgram.h"
#endif

#include <array>
#include <vector>
#include <string>

namespace JWT {
	using SHA256Hash = std::array<uint8_t, 32>;
	using ByteData = std::vector<uint8_t>;

	struct JWTContent
	{
		std::string header;
		std::string payload;
		ByteData signature;
	};

	std::string base64Encode(const ByteData& input);
	ByteData base64Decode(const std::string& input);
	std::string base64URLEncode(const ByteData& input);
	ByteData base64URLDecode(const std::string& input);

	ByteData signWithKeyFile(const ByteData& data, const std::string& privateKeyPath);
	ByteData signWithKey(const ByteData& data, const std::string& privateKey);
	bool verifyWithKeyFile(const ByteData& data, const ByteData& signature, const std::string& publicKeyPath);
	bool verifyWithKey(const ByteData& data, const ByteData& signature, const std::string& publicKey);

	JWTContent parse(const std::string& jwt);
};

#endif

