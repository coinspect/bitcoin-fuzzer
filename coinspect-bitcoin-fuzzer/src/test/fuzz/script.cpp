// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <compressor.h>
#include <core_io.h>
#include <core_memusage.h>
#include <key_io.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <univalue.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <ctype.h>
#include <stdio.h>

typedef std::basic_string <unsigned char> ustring;

std::vector<unsigned char> CheckedParseHex(const std::string& str)
{   
	if (str.size() && !IsHex(str)) throw std::runtime_error("Non-hex input '" + str + "'");
	return ParseHex(str);
}

CScript ScriptFromHex(const std::string& str)
{   
	std::vector<unsigned char> data = CheckedParseHex(str);
	return CScript(data.begin(), data.end());
}

void hexdump(const unsigned char *ptr, int buflen)
{
	unsigned char	*buf = (unsigned char*) ptr;
	int				i, j;

	for (i = 0; i < buflen; i += 16) {
		printf("%06x: ", i);
		for (j = 0; j < 16; j++) 
			if (i + j < buflen)
				printf("%02x ", buf[i+j]);
			else
				printf("   ");
		printf(" ");
		for (j = 0; j < 16; j++) 
			if (i + j < buflen)
				printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
		printf("\n");
	}
}

std::string checkTrueOrFalse(bool value)
{
	return value ? "true" : "false";
} 

void initialize_script()
{
    // Fuzzers using pubkey must hold an ECCVerifyHandle.
    static const ECCVerifyHandle verify_handle;

    SelectParams(CBaseChainParams::REGTEST);
}

void check_type(TxoutType which_type)
{
	if (which_type == TxoutType::NONSTANDARD)
		 std::cout << "   Type :: NONSTANDARD" << "\n";
	if (which_type == TxoutType::NULL_DATA)
		std::cout << "    Type :: NULL_DATA" << "\n";
	if (which_type == TxoutType::MULTISIG)
		 std::cout << "   Type :: MULTISIG" << "\n";
	if (which_type == TxoutType::PUBKEY)
		std::cout << "    Type :: PUBKEY" << "\n";
	if (which_type == TxoutType::PUBKEYHASH)
		std::cout << "    Type :: PUBKEYHASH" << "\n";
	if (which_type == TxoutType::SCRIPTHASH)
		std::cout << "    Type :: SCRIPTHASH" << "\n";
	if (which_type == TxoutType::WITNESS_V0_SCRIPTHASH)
		std::cout << "    Type :: WITNESS_V0_SCRIPTHASH" << "\n";
	if (which_type == TxoutType::WITNESS_V0_KEYHASH)
		std::cout << "    Type :: WITNESS_V0_KEYHASH" << "\n";
	if (which_type == TxoutType::WITNESS_V1_TAPROOT)
		std::cout << "    Type :: WITNESS_V1_TAPROOT" << "\n";
	if (which_type == TxoutType::WITNESS_UNKNOWN)
		std::cout << "    Type :: WITNESS_UNKNOWN" << "\n";
}


FUZZ_TARGET_INIT(script, initialize_script)
{
#if 0
	std::cout << "\n\n";
	printf("Input :: %u", (unsigned int) buffer.size());
	std::cout << "\n";
	hexdump(buffer.data(), buffer.size());
#endif
	std::string input = std::string(reinterpret_cast<const std::string::value_type *>(buffer.begin()), (buffer.size()));

	std::vector <std::string> scripts;

	CScript scriptSig_input;
	CScript scriptPubKey_input;
	TxoutType which_type;

	std::string	unlockScriptToken = "\"script\":";
	std::string lockScriptToken = "\"lockScript\":";
	std::string delimiter = "\",";

	std::size_t foundUnlockScript = 0;
	std::size_t foundLockScript = 0;
	size_t		pos = 0;
	int			num = 0;

	while ((foundUnlockScript != std::string::npos) && (foundLockScript != std::string::npos)) {
		std::string unlockScript;
		std::string lockScript;
		std::size_t len;
		std::size_t offset;

		foundUnlockScript = input.find(unlockScriptToken, pos);
		pos = foundUnlockScript + unlockScriptToken.length();
		foundLockScript = input.find(lockScriptToken, pos);
		pos = foundLockScript + lockScriptToken.length();

		if (foundUnlockScript != std::string::npos) {
			offset = foundUnlockScript + unlockScriptToken.length() + 1;
			pos = input.find(delimiter, offset);
			len = pos - offset;
			unlockScript = input.substr(offset, len);

			scripts.push_back(unlockScript);
		}
		if (foundLockScript != std::string::npos) {
			offset = foundLockScript + lockScriptToken.length() + 1;
			pos = input.find(delimiter, offset);
			len = pos - offset;
			lockScript = input.substr(offset, len);

			scripts.push_back(lockScript);
		}

		scriptSig_input = ScriptFromHex(unlockScript);
		scriptPubKey_input = ScriptFromHex(lockScript);

		if (scriptPubKey_input.GetSigOpCount(scriptSig_input) > MAX_P2SH_SIGOPS) {
			std::cout << std::endl;
			std::cout << "NON-STANDARD SCRIPT" << std::endl;
			std::cout << std::endl;
			std::cout << "  scriptPuKey :: " << (scriptPubKey_input.size()) << std::endl;
 			std::cout << "    IsStandard :: " << checkTrueOrFalse(IsStandard(scriptPubKey_input, std::nullopt, which_type)) << std::endl;
			std::cout << "    IsPayToScriptHash :: " << checkTrueOrFalse(scriptPubKey_input.IsPayToScriptHash()) << std::endl;
			check_type(which_type);
			std::cout << lockScript << std::endl;
			std::cout << std::endl;
			std::cout << "  scriptSig :: " << (scriptSig_input.size()) << std::endl;
			std::cout << "    GetSigOpCount :: " << scriptPubKey_input.GetSigOpCount(scriptSig_input) << std::endl;
			std::cout << "    AreInputsStandard::GetSigOpCount(true) < MAX_P2SH_SIGOPS :: " << \
				checkTrueOrFalse(scriptPubKey_input.GetSigOpCount(scriptSig_input) < MAX_P2SH_SIGOPS);
			std::cout << std::endl;
			check_type(which_type);
			std::cout << unlockScript << std::endl;
			std::cout << std::endl << std::endl;
		}

		assert(scriptPubKey_input.GetSigOpCount(scriptSig_input) < MAX_P2SH_SIGOPS);

		num++;
	}


    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const CScript script{ConsumeScript(fuzzed_data_provider)};
    CompressedScript compressed;

   if (CompressScript(script, compressed)) {
        const unsigned int size = compressed[0];
        compressed.erase(compressed.begin());
        assert(size <= 5);
        CScript decompressed_script;
        const bool ok = DecompressScript(decompressed_script, size, compressed);
        assert(ok);
        assert(script == decompressed_script);
    }

    bool is_standard_ret = IsStandard(script, std::nullopt, which_type);
	
    if (!is_standard_ret) {
        assert(which_type == TxoutType::NONSTANDARD ||
               which_type == TxoutType::NULL_DATA ||
               which_type == TxoutType::MULTISIG);
    }
    if (which_type == TxoutType::NONSTANDARD) {
        assert(!is_standard_ret);
    }
    if (which_type == TxoutType::NULL_DATA) {
        assert(script.IsUnspendable());
    }
    if (script.IsUnspendable()) {
        assert(which_type == TxoutType::NULL_DATA ||
               which_type == TxoutType::NONSTANDARD);
    }

    CTxDestination address;
    bool extract_destination_ret = ExtractDestination(script, address);
    if (!extract_destination_ret) {
        assert(which_type == TxoutType::PUBKEY ||
               which_type == TxoutType::NONSTANDARD ||
               which_type == TxoutType::NULL_DATA ||
               which_type == TxoutType::MULTISIG);
    }
    if (which_type == TxoutType::NONSTANDARD ||
        which_type == TxoutType::NULL_DATA ||
        which_type == TxoutType::MULTISIG) {
        assert(!extract_destination_ret);
    }

    const FlatSigningProvider signing_provider;
    (void)InferDescriptor(script, signing_provider);
    (void)IsSegWitOutput(signing_provider, script);

    (void)RecursiveDynamicUsage(script);

    std::vector<std::vector<unsigned char>> solutions;
    (void)Solver(script, solutions);

    (void)script.HasValidOps();
    (void)script.IsPayToScriptHash();
    (void)script.IsPayToWitnessScriptHash();
    (void)script.IsPushOnly();
    (void)script.GetSigOpCount(/* fAccurate= */ false);

    {
        const std::vector<uint8_t> bytes = ConsumeRandomLengthByteVector(fuzzed_data_provider);
        CompressedScript compressed_script;
        compressed_script.assign(bytes.begin(), bytes.end());
        // DecompressScript(..., ..., bytes) is not guaranteed to be defined if the bytes vector is too short
        if (compressed_script.size() >= 32) {
            CScript decompressed_script;
            DecompressScript(decompressed_script, fuzzed_data_provider.ConsumeIntegral<unsigned int>(), compressed_script);
        }
    }

    const std::optional<CScript> other_script = ConsumeDeserializable<CScript>(fuzzed_data_provider);
    if (other_script) {
        {
            CScript script_mut{script};
            (void)FindAndDelete(script_mut, *other_script);
        }
        const std::vector<std::string> random_string_vector = ConsumeRandomLengthStringVector(fuzzed_data_provider);
        const uint32_t u32{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
        const uint32_t flags{u32 | SCRIPT_VERIFY_P2SH};
        {
            CScriptWitness wit;
            for (const auto& s : random_string_vector) {
                wit.stack.emplace_back(s.begin(), s.end());
            }
            (void)CountWitnessSigOps(script, *other_script, &wit, flags);
            wit.SetNull();
        }
    }

    (void)GetOpName(ConsumeOpcodeType(fuzzed_data_provider));
    (void)ScriptErrorString(static_cast<ScriptError>(fuzzed_data_provider.ConsumeIntegralInRange<int>(0, SCRIPT_ERR_ERROR_COUNT)));

    {
        const std::vector<uint8_t> bytes = ConsumeRandomLengthByteVector(fuzzed_data_provider);
        CScript append_script{bytes.begin(), bytes.end()};
        append_script << fuzzed_data_provider.ConsumeIntegral<int64_t>();
        append_script << ConsumeOpcodeType(fuzzed_data_provider);
        append_script << CScriptNum{fuzzed_data_provider.ConsumeIntegral<int64_t>()};
        append_script << ConsumeRandomLengthByteVector(fuzzed_data_provider);
    }

    {
        const CTxDestination tx_destination_1{
            fuzzed_data_provider.ConsumeBool() ?
                DecodeDestination(fuzzed_data_provider.ConsumeRandomLengthString()) :
                ConsumeTxDestination(fuzzed_data_provider)};
        const CTxDestination tx_destination_2{ConsumeTxDestination(fuzzed_data_provider)};
        const std::string encoded_dest{EncodeDestination(tx_destination_1)};
        const UniValue json_dest{DescribeAddress(tx_destination_1)};
        Assert(tx_destination_1 == DecodeDestination(encoded_dest));
        (void)GetKeyForDestination(/*store=*/{}, tx_destination_1);
        const CScript dest{GetScriptForDestination(tx_destination_1)};
        const bool valid{IsValidDestination(tx_destination_1)};
        Assert(dest.empty() != valid);

        Assert(valid == IsValidDestinationString(encoded_dest));

        (void)(tx_destination_1 < tx_destination_2);
        if (tx_destination_1 == tx_destination_2) {
            Assert(encoded_dest == EncodeDestination(tx_destination_2));
            Assert(json_dest.write() == DescribeAddress(tx_destination_2).write());
            Assert(dest == GetScriptForDestination(tx_destination_2));
        }
    }
}
