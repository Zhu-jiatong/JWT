/*
 Name:		JWT.cpp
 Created:	8/23/2024 8:35:44 PM
 Author:	zhuji
 Editor:	http://www.visualmicro.com
*/

#include "JWT.h"
#include <mbedtls/base64.h>
#include <algorithm>
#include <stdexcept>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/error.h>

std::string JWT::base64Encode(const ByteData& input)
{
	const uint8_t* inputBuffer = reinterpret_cast<const uint8_t*>(input.data());
	size_t bufferSize;
	mbedtls_base64_encode(nullptr, 0, &bufferSize, inputBuffer, input.size());

	ByteData output(bufferSize);
	size_t outputSize;
	int rc = mbedtls_base64_encode(reinterpret_cast<unsigned char*>(output.data()), bufferSize, &outputSize, inputBuffer, input.size());
	if (rc == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
		throw std::runtime_error("Buffer too small");

	return { output.begin(), std::next(output.begin(), outputSize) };
}

JWT::ByteData JWT::base64Decode(const std::string& input)
{
	const uint8_t* inputBuffer = reinterpret_cast<const uint8_t*>(input.data());
	size_t bufferSize;
	{
		int rc = mbedtls_base64_decode(nullptr, 0, &bufferSize, inputBuffer, input.size());
		if (rc == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
			throw std::invalid_argument("Invalid character");
	}

	ByteData output(bufferSize);
	size_t outputSize;
	{
		int rc = mbedtls_base64_decode(output.data(), output.size(), &outputSize, inputBuffer, input.size());
		if (rc == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
			throw std::invalid_argument("Invalid character");
		if (rc == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
			throw std::runtime_error("Buffer too small");
	}

	return output;
}

std::string JWT::base64URLEncode(const ByteData& input)
{
	std::string output = base64Encode(input);

	std::erase_if(output, [](char c) { return c == '='; });
	std::ranges::replace(output, '+', '-');
	std::ranges::replace(output, '/', '_');

	return output;
}

JWT::ByteData JWT::base64URLDecode(const std::string& input)
{
	std::string output = input;

	std::ranges::replace(output, '-', '+');
	std::ranges::replace(output, '_', '/');
	switch (output.size() % 4)
	{
	case 0:
		break;
	case 2:
		output += "==";
		break;
	case 3:
		output += "=";
		break;

	default:
		throw std::invalid_argument("Invalid base64 string");
	}

	return base64Decode(output);
}

JWT::ByteData JWT::signWithKeyFile(const ByteData& data, const std::string& privateKeyPath)
{
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	mbedtls_pk_parse_keyfile(&pk, privateKeyPath.c_str(), nullptr, mbedtls_ctr_drbg_random, &ctr_drbg);

	SHA256Hash hash;
	mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data.data(), data.size(), hash.data());

	std::array<uint8_t, MBEDTLS_PK_SIGNATURE_MAX_SIZE> signature;
	size_t signatureSize;
	mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash.data(), hash.size(), signature.data(), signature.size(), &signatureSize, mbedtls_ctr_drbg_random, &ctr_drbg);

	mbedtls_pk_free(&pk);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return { signature.begin(), std::next(signature.begin(), signatureSize) };
}

JWT::ByteData JWT::signWithKey(const ByteData& data, const std::string& privateKey)
{
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	mbedtls_pk_parse_key(&pk, reinterpret_cast<const uint8_t*>(privateKey.c_str()), privateKey.size() + 1, nullptr, 0, mbedtls_ctr_drbg_random, &ctr_drbg);

	SHA256Hash hash;
	mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data.data(), data.size(), hash.data());

	std::array<uint8_t, MBEDTLS_PK_SIGNATURE_MAX_SIZE> signature;
	size_t signatureSize;
	mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash.data(), hash.size(), signature.data(), signature.size(), &signatureSize, mbedtls_ctr_drbg_random, &ctr_drbg);

	mbedtls_pk_free(&pk);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return { signature.begin(), std::next(signature.begin(), signatureSize) };
}

bool JWT::verifyWithKeyFile(const ByteData& data, const ByteData& signature, const std::string& publicKeyPath)
{
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	{
		int rc = mbedtls_pk_parse_public_keyfile(&pk, publicKeyPath.c_str());
		if (rc != 0)
			throw std::runtime_error("Failed to parse public key file");
	}

	SHA256Hash hash;
	mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data.data(), data.size(), hash.data());

	int rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash.data(), hash.size(), signature.data(), signature.size());
	if (rc == 0 || rc == MBEDTLS_ERR_PK_SIG_LEN_MISMATCH)
		return true;

	return false;
}

bool JWT::verifyWithKey(const ByteData& data, const ByteData& signature, const std::string& publicKey)
{
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	mbedtls_pk_parse_public_key(&pk, reinterpret_cast<const uint8_t*>(publicKey.c_str()), publicKey.size() + 1);

	SHA256Hash hash;
	mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data.data(), data.size(), hash.data());

	int rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash.data(), hash.size(), signature.data(), signature.size());
	if (rc == 0 || rc == MBEDTLS_ERR_PK_SIG_LEN_MISMATCH)
		return true;

	return false;
}

JWT::JWTContent JWT::parse(const std::string& jwt)
{
	size_t headerEnd = jwt.find('.');
	if (headerEnd == std::string::npos)
		throw std::invalid_argument("Invalid JWT");

	size_t payloadEnd = jwt.find('.', headerEnd + 1);
	if (payloadEnd == std::string::npos)
		throw std::invalid_argument("Invalid JWT");

	std::string base64Header = jwt.substr(0, headerEnd);
	std::string base64Payload = jwt.substr(headerEnd + 1, payloadEnd - headerEnd - 1);
	std::string base64Signature = jwt.substr(payloadEnd + 1);

	ByteData rawHeader = base64URLDecode(base64Header);
	ByteData rawPayload = base64URLDecode(base64Payload);
	ByteData rawSignature = base64URLDecode(base64Signature);

	std::string header(rawHeader.begin(), rawHeader.end());
	std::string payload(rawPayload.begin(), rawPayload.end());

	return { header, payload, rawSignature };
}
