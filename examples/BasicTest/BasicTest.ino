/*
 Name:		BasicTest.ino
 Created:	8/23/2024 8:36:11 PM
 Author:	zhuji
*/

#include "JWT.h"
#include <iostream>
#include <SD.h>
#include <iomanip>

// the setup function runs once when you press reset or power the board
void setup()
{
	Serial.begin(115200);

	try
	{
		if (!SD.begin(SS, SPI, 80000000))
			throw std::runtime_error("SD card initialization failed");

		// test base64URL encode
		{
			std::string input = "Hello, world!";
			std::string encoded = JWT::base64URLEncode({ input.begin(), input.end() });
			std::cout << "Base64 URL encoded: " << encoded << std::endl;
		}

		// test base64URL decode
		{
			std::string input = "SGVsbG8sIHdvcmxkIQ";
			JWT::ByteData decoded = JWT::base64URLDecode(input);
			std::string decodedStr(decoded.begin(), decoded.end());
			std::cout << "Base64 URL decoded: " << decodedStr << std::endl;
		}

		// test sign with key file
		{
			std::string data = "Hello, world!";
			JWT::ByteData signature = JWT::signWithKeyFile({ data.begin(), data.end() }, "/sd/test.pem");
			std::cout << "Signature (HEX): ";
			for (auto byte : signature)
				std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			std::cout << std::endl;
			std::string signatureStr = JWT::base64URLEncode(signature);
			std::cout << "Signature (Base64 URL): " << signatureStr << std::endl;
		}

		// test verify with key file
		{
			std::string data = "Hello, world!";
			JWT::ByteData signature = JWT::signWithKeyFile({ data.begin(), data.end() }, "/sd/test.pem");
			std::cout << "Signature (HEX): ";
			for (auto byte : signature)
				std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			std::cout << std::endl;
			std::string signatureStr = JWT::base64URLEncode(signature);
			std::cout << "Signature (Base64 URL): " << signatureStr << std::endl;
			bool verified = JWT::verifyWithKeyFile({ data.begin(), data.end() }, signature, "/sd/test.pub.pem");
			std::cout << "Verified: " << std::boolalpha << verified << std::endl;
		}

		// test parse
		{
			const std::string rawJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";
			JWT::JWTContent content = JWT::parse(rawJWT);
			std::cout << "Header: " << content.header << std::endl;
			std::cout << "Payload: " << content.payload << std::endl;
			printSignature(content.signature);

			const std::string publicKey = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----)";
			const std::string data = JWT::base64URLEncode({ content.header.begin(), content.header.end() }) + "." + JWT::base64URLEncode({ content.payload.begin(), content.payload.end() });
			bool verified = JWT::verifyWithKey({ data.begin(), data.end() }, content.signature, publicKey);
			std::cout << "Verified: " << std::boolalpha << verified << std::endl;
		}
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}
}

// the loop function runs over and over again until power down or reset
void loop()
{

}

void printSignature(const JWT::ByteData& signature)
{
	std::cout << "Signature (HEX): ";
	for (auto byte : signature)
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
	std::cout << std::endl;
	std::string signatureStr = JWT::base64URLEncode(signature);
	std::cout << "Signature (Base64 URL): " << signatureStr << std::endl;
}