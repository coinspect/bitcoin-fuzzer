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

#include <test/util/transaction_utils.h>
#include <util/strencodings.h>
#include <test/data/script_tests.json.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <ctype.h>
#include <stdio.h>


std::string FormatScriptFlags(unsigned int flags);
typedef std::basic_string <unsigned char> ustring;

static std::map<std::string, unsigned int> mapFlagNames = {
    {std::string("P2SH"), (unsigned int)SCRIPT_VERIFY_P2SH},
    {std::string("STRICTENC"), (unsigned int)SCRIPT_VERIFY_STRICTENC},
    {std::string("DERSIG"), (unsigned int)SCRIPT_VERIFY_DERSIG},
    {std::string("LOW_S"), (unsigned int)SCRIPT_VERIFY_LOW_S},
    {std::string("SIGPUSHONLY"), (unsigned int)SCRIPT_VERIFY_SIGPUSHONLY},
    {std::string("MINIMALDATA"), (unsigned int)SCRIPT_VERIFY_MINIMALDATA},
    {std::string("NULLDUMMY"), (unsigned int)SCRIPT_VERIFY_NULLDUMMY},
    {std::string("DISCOURAGE_UPGRADABLE_NOPS"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS},
    {std::string("CLEANSTACK"), (unsigned int)SCRIPT_VERIFY_CLEANSTACK},
    {std::string("MINIMALIF"), (unsigned int)SCRIPT_VERIFY_MINIMALIF},
    {std::string("NULLFAIL"), (unsigned int)SCRIPT_VERIFY_NULLFAIL},
    {std::string("CHECKLOCKTIMEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY},
    {std::string("CHECKSEQUENCEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKSEQUENCEVERIFY},
    {std::string("WITNESS"), (unsigned int)SCRIPT_VERIFY_WITNESS},
    {std::string("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM},
    {std::string("WITNESS_PUBKEYTYPE"), (unsigned int)SCRIPT_VERIFY_WITNESS_PUBKEYTYPE},
    {std::string("CONST_SCRIPTCODE"), (unsigned int)SCRIPT_VERIFY_CONST_SCRIPTCODE},
    {std::string("TAPROOT"), (unsigned int)SCRIPT_VERIFY_TAPROOT},
    {std::string("DISCOURAGE_UPGRADABLE_PUBKEYTYPE"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE},
    {std::string("DISCOURAGE_OP_SUCCESS"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS},
    {std::string("DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION},
};

struct ScriptErrorDesc
{
    ScriptError_t err;
    const char *name;
};

static ScriptErrorDesc script_errors[]={
    {SCRIPT_ERR_OK, "OK"},
    {SCRIPT_ERR_UNKNOWN_ERROR, "UNKNOWN_ERROR"},
    {SCRIPT_ERR_EVAL_FALSE, "EVAL_FALSE"},
    {SCRIPT_ERR_OP_RETURN, "OP_RETURN"},
    {SCRIPT_ERR_SCRIPT_SIZE, "SCRIPT_SIZE"},
    {SCRIPT_ERR_PUSH_SIZE, "PUSH_SIZE"},
    {SCRIPT_ERR_OP_COUNT, "OP_COUNT"},
    {SCRIPT_ERR_STACK_SIZE, "STACK_SIZE"},
    {SCRIPT_ERR_SIG_COUNT, "SIG_COUNT"},
    {SCRIPT_ERR_PUBKEY_COUNT, "PUBKEY_COUNT"},
    {SCRIPT_ERR_VERIFY, "VERIFY"},
    {SCRIPT_ERR_EQUALVERIFY, "EQUALVERIFY"},
    {SCRIPT_ERR_CHECKMULTISIGVERIFY, "CHECKMULTISIGVERIFY"},
    {SCRIPT_ERR_CHECKSIGVERIFY, "CHECKSIGVERIFY"},
    {SCRIPT_ERR_NUMEQUALVERIFY, "NUMEQUALVERIFY"},
    {SCRIPT_ERR_BAD_OPCODE, "BAD_OPCODE"},
    {SCRIPT_ERR_DISABLED_OPCODE, "DISABLED_OPCODE"},
    {SCRIPT_ERR_INVALID_STACK_OPERATION, "INVALID_STACK_OPERATION"},
    {SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "INVALID_ALTSTACK_OPERATION"},
    {SCRIPT_ERR_UNBALANCED_CONDITIONAL, "UNBALANCED_CONDITIONAL"},
    {SCRIPT_ERR_NEGATIVE_LOCKTIME, "NEGATIVE_LOCKTIME"},
    {SCRIPT_ERR_UNSATISFIED_LOCKTIME, "UNSATISFIED_LOCKTIME"},
    {SCRIPT_ERR_SIG_HASHTYPE, "SIG_HASHTYPE"},
    {SCRIPT_ERR_SIG_DER, "SIG_DER"},
    {SCRIPT_ERR_MINIMALDATA, "MINIMALDATA"},
    {SCRIPT_ERR_SIG_PUSHONLY, "SIG_PUSHONLY"},
    {SCRIPT_ERR_SIG_HIGH_S, "SIG_HIGH_S"},
    {SCRIPT_ERR_SIG_NULLDUMMY, "SIG_NULLDUMMY"},
    {SCRIPT_ERR_PUBKEYTYPE, "PUBKEYTYPE"},
    {SCRIPT_ERR_CLEANSTACK, "CLEANSTACK"},
    {SCRIPT_ERR_MINIMALIF, "MINIMALIF"},
    {SCRIPT_ERR_SIG_NULLFAIL, "NULLFAIL"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "DISCOURAGE_UPGRADABLE_NOPS"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH, "WITNESS_PROGRAM_WRONG_LENGTH"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY, "WITNESS_PROGRAM_WITNESS_EMPTY"},
    {SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "WITNESS_PROGRAM_MISMATCH"},
    {SCRIPT_ERR_WITNESS_MALLEATED, "WITNESS_MALLEATED"},
    {SCRIPT_ERR_WITNESS_MALLEATED_P2SH, "WITNESS_MALLEATED_P2SH"},
    {SCRIPT_ERR_WITNESS_UNEXPECTED, "WITNESS_UNEXPECTED"},
    {SCRIPT_ERR_WITNESS_PUBKEYTYPE, "WITNESS_PUBKEYTYPE"},
    {SCRIPT_ERR_OP_CODESEPARATOR, "OP_CODESEPARATOR"},
    {SCRIPT_ERR_SIG_FINDANDDELETE, "SIG_FINDANDDELETE"},
};

void Hexdump(const unsigned char *ptr, int buflen)
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

unsigned int ParseScriptFlags(std::string strFlags)
{
    if (strFlags.empty() || strFlags == "NONE") return 0;
    unsigned int flags = 0;
    std::vector<std::string> words = SplitString(strFlags, ',');

    for (const std::string& word : words)
    {
        if (!mapFlagNames.count(word))
            std::cout << "Bad test: unknown verification flag '" << word << "'" << std::endl;
        flags |= mapFlagNames[word];
    }

    return flags;
}

std::vector<unsigned char> CheckedParseHex(const std::string& str)
{   
	if (str.size() && !IsHex(str)) throw std::runtime_error("Non-hex input '" + str + "'");
	return ParseHex(str);
}

static std::string FormatScriptError(ScriptError_t err)
{
    for (const auto& se : script_errors) {
        if (se.err == err)
            return se.name;
	}
	std::cout << "Unknown scripterror enumeration value, update script_errors in script_tests.cpp." << std::endl;
    return "";
}

static ScriptError_t ParseScriptError(const std::string& name)
{
    for (const auto& se : script_errors) {
        if (se.name == name)
            return se.err;
	}
	std::cout << "Unknown scripterror \"" << name << "\" in test description" << std::endl;
    return SCRIPT_ERR_UNKNOWN_ERROR;
}

CScript ScriptFromHex(const std::string& str)
{   
	std::vector<unsigned char> data = CheckedParseHex(str);
	return CScript(data.begin(), data.end());
}

void checkType(TxoutType which_type)
{
	if (which_type == TxoutType::NONSTANDARD)
		std::cout << "    Type :: NONSTANDARD" << "\n";
	if (which_type == TxoutType::NULL_DATA)
		std::cout << "    Type :: NULL_DATA" << "\n";
	if (which_type == TxoutType::MULTISIG)
		std::cout << "    Type :: MULTISIG" << "\n";
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

UniValue read_json(const std::string& jsondata)
{
    UniValue v;

    if (!v.read(jsondata) || !v.isArray())
    {   
		std::cout << "Parse error." << std::endl;
        return UniValue(UniValue::VARR);
    }
    return v.get_array();
}

void PRINT_SCRIPTS_SUMMARY(CScript scriptSig_input, CScript scriptPubKey_input)
{
    TxoutType which_type;

	std::cout << std::endl;
	std::cout << "NON-STANDARD SCRIPT" << std::endl;
	std::cout << std::endl;
	std::cout << "  scriptPuKey :: " << (scriptPubKey_input.size()) << std::endl;
	std::cout << "    IsStandard :: " << checkTrueOrFalse(IsStandard(scriptPubKey_input, std::nullopt, which_type)) << std::endl;
	std::cout << "    IsPayToScriptHash :: " << checkTrueOrFalse(scriptPubKey_input.IsPayToScriptHash()) << std::endl;
	checkType(which_type);
	std::cout << "    HEX :: " << HexStr(scriptPubKey_input) << std::endl;
	std::cout << "    ASM :: " << ScriptToAsmStr(scriptPubKey_input, false) << std::endl;
	std::cout << std::endl;

	std::cout << "  scriptSig :: " << (scriptSig_input.size()) << std::endl;
	std::cout << "    GetSigOpCount :: " << scriptPubKey_input.GetSigOpCount(scriptSig_input) << std::endl;
	std::cout << "    AreInputsStandard::GetSigOpCount(true) < MAX_P2SH_SIGOPS :: " << \
		checkTrueOrFalse(scriptPubKey_input.GetSigOpCount(scriptSig_input) < MAX_P2SH_SIGOPS) << std::endl;
#if PEGFIX_PATCH
	// Sergio's patch to script parser
	std::size_t sigOpCount = scriptSig_input.GetStandardSigOpCount();
	std::cout << "    GetStandardSigOpCount == " << sigOpCount;
	std::cout << std::endl;
#endif
	checkType(which_type);
	std::cout << "    HEX :: " << HexStr(scriptSig_input) << std::endl;
	std::cout << "    ASM :: " << ScriptToAsmStr(scriptSig_input, true) << std::endl;
	std::cout << std::endl << std::endl;
}

void initialize_script()
{
    // Fuzzers using pubkey must hold an ECCVerifyHandle.
    static const ECCVerifyHandle verify_handle;

    SelectParams(CBaseChainParams::REGTEST);
}

FUZZ_TARGET_INIT(script, initialize_script)
{
	std::string input = std::string(reinterpret_cast<const std::string::value_type *>(buffer.begin()), (buffer.size()));
	std::vector <std::string> scripts;

	TxoutType which_type;
	std::size_t count = 0;

#if BITCOIN_FUZZER_USE_OLD_JSON_PASRSER
	// Old parser
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

		PRINT_SCRIPTS_SUMMARY(unlockScript, lockScript);

		num++;
	}
#else
    // Read tests from test/data/script_tests.json
    // Format is an array of arrays
    // Inner arrays are [ ["wit"..., nValue]?, "scriptSig", "scriptPubKey", "flags", "expected_scripterror" ]
    // ... where scriptSig and scriptPubKey are stringified
    // scripts.
    // If a witness is given, then the last value in the array should be the
    // amount (nValue) to use in the crediting tx
    UniValue tests = read_json(std::string(json_tests::script_tests, json_tests::script_tests + sizeof(json_tests::script_tests)));

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        CScriptWitness witness;
        std::string strWitness;
        CAmount nValue = 0;
        unsigned int pos = 0;
        if (test.size() > 0 && test[pos].isArray()) {
            unsigned int i=0;
            for (i = 0; i < test[pos].size()-1; i++) {
                witness.stack.push_back(ParseHex(test[pos][i].get_str()));
                strWitness = test[pos][i].get_str();
            }
            nValue = AmountFromValue(test[pos][i]);
            pos++;
        }
        if (test.size() < 4 + pos) // Allow size > 3; extra stuff ignored (useful for comments)
        {   
            if (test.size() != 1) {
				std::cout << "Bad test: " << strTest << std::endl;
            }
            continue;
        }
		// BITCOIN-FUZZER: Printing parsed data for user's clarity. Can be removed in the future.
        std::cout << "[" << count++ << "] " << "==============================================" << std::endl;
        std::cout << std::endl;
        std::cout << "JSON INPUT" << std::endl << std::endl;
		std::cout << "amount :: " << nValue << std::endl;
        std::cout << "witness :: " << strWitness << std::endl;
        std::string scriptSigString = test[pos++].get_str();
        std::cout << "scriptSig :: " << scriptSigString << std::endl;
        std::string scriptPubKeyString = test[pos++].get_str();
        std::cout << "scriptPubKey :: " << scriptPubKeyString << std::endl;

        CScript scriptSig = ParseScript(scriptSigString);
        CScript scriptPubKey = ParseScript(scriptPubKeyString);

		std::string strScriptflags = test[pos].get_str();
        unsigned int scriptflags = ParseScriptFlags(test[pos++].get_str());
		std::cout << "flags :: " << strScriptflags << " | " << scriptflags << std::endl;

		std::string strScriptError = test[pos].get_str();
        int scriptError = ParseScriptError(test[pos++].get_str());
		std::cout << "error :: " << strScriptError << " | " << scriptError << std::endl;

        PRINT_SCRIPTS_SUMMARY(scriptSig, scriptPubKey);
    }
#endif

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
