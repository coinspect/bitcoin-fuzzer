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

	std::string	lockScriptToken = "\"lockScript\":";
	std::string	unlockScriptToken = "\"unlockScript\":";

	std::string	timeLockToken = "\"timelock\":";
	std::string timeLockDelimiter = ",\"";
	std::string	scriptToken = "\"script\":";
	std::string scriptDelimiter = "\"},";

	std::size_t foundTimeLock = input.find(timeLockToken);
	std::size_t foundScript = input.find(scriptToken);
	size_t		pos = 0;
	int			num = 0;

	while (foundTimeLock != std::string::npos) {
		std::string timelock;
		std::string script;
		std::size_t len;
		std::size_t offset;

		foundTimeLock = input.find(timeLockToken, pos);
		pos = foundTimeLock + timeLockToken.length();
		foundScript = input.find(scriptToken, pos);
		pos = foundScript + scriptToken.length();

		if (foundTimeLock != std::string::npos) {
			offset = foundTimeLock + timeLockToken.length();
			pos = input.find(timeLockDelimiter, offset);
			len = pos - offset;
			timelock = input.substr(offset, len);

			std::cout << "'Time Lock' found at: " << foundTimeLock << '\n';
			std::cout << ">>> " << timelock << '\n';
		}
		if (foundScript != std::string::npos) {
			offset = foundScript + scriptToken.length();
			pos = input.find(scriptDelimiter, offset);
			len = pos - offset;
			script = input.substr(offset, len);

			std::cout << "'Script' found at: " << foundScript << '\n';
			std::cout << ">>> " << script << '\n';
		}
		num++;
	}
	std::cout << "Total scripts found: " << num << '\n';

    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const CScript script{ConsumeScript(fuzzed_data_provider)};
    CompressedScript compressed;
	TxoutType which_type;

#if 0
	const CScript scriptPubKey_sampleP2PK = ScriptFromHex("4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac");
	const CScript scriptPubKey_sampleP2PKH = ScriptFromHex("76a91412ab8dc588ca9d5787dde7eb29569da63c3a238c88ac");
	const CScript scriptPubKey_sampleP2SH = ScriptFromHex("a914748284390f9e263a4b766a75d0633c50426eb87587");
	const CScript scriptPubKey_deprecateERP = ScriptFromHex("a9145938886a96ffa30ba7f3a7a55350adb0b069b97787");
	const CScript scriptPubKey_newERP =	ScriptFromHex("a914bf78f42f55944803b78752ab66063e685ab53f2287");

	const CScript scriptSig_sampleP2PK = ScriptFromHex("4730440220576497b7e6f9b553c0aba0d8929432550e092db9c130aae37b84b545e7f4a36c022066cb982ed80608372c139d7bb9af335423d5280350fe3e06bd510e695480914f01");
	const CScript scriptSig_sampleP2PKH = ScriptFromHex("48304502203f004eeed0cef2715643e2f25a27a28f3c578e94c7f0f6a4df104e7d163f7f8f022100b8b248c1cfd8f77a0365107a9511d759b7544d979dd152a955c867afac0ef7860141044d05240cfbd8a2786eda9dadd520c1609b8593ff8641018d57703d02ba687cf2f187f0cee2221c3afb1b5ff7888caced2423916b61444666ca1216f26181398c");
	const CScript scriptSig_sampleP2SH = ScriptFromHex("00493046022100a07b2821f96658c938fa9c68950af0e69f3b2ce5f8258b3a6ad254d4bc73e11e022100e82fab8df3f7e7a28e91b3609f91e8ebf663af3a4dc2fd2abd954301a5da67e701475121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae");
	const CScript scriptSig_deprecateERP = ScriptFromHex("00473045022100d7912c828f4fe5aa1194762b9cc4ce7164ec78f43e724e0d29a24ea883530fcc02203a80f8d843011b8ab0c9462dc46970c17ada4aae39d1e4fc0dc01b59522677bc473045022100d7912c828f4fe5aa1194762b9cc4ce7164ec78f43e724e0d29a24ea883530fcc02203a80f8d843011b8ab0c9462dc46970c17ada4aae39d1e4fc0dc01b59522677bc4c95645221020a6011786c4f54cb3cebde468bccd518573154897c48bd69fcf9f392a9aa56bd21024ff8ca686fd9f125489d4a56e967b467af6dee9bd944062d8e2bd4ad377934512103e99bd5148fc9bee81ca86e5c8933bee659f909fdf482126cc9b6f037fead50255367020001b275512102199fa8ade567942c1c07a44ac4e449f0bda515d41809a1e5d5997f39fcdb255c5168ae");
	const CScript scriptSig_newERP = ScriptFromHex("00473045022100d7912c828f4fe5aa1194762b9cc4ce7164ec78f43e724e0d29a24ea883530fcc02203a80f8d843011b8ab0c9462dc46970c17ada4aae39d1e4fc0dc01b59522677bc473045022100d7912c828f4fe5aa1194762b9cc4ce7164ec78f43e724e0d29a24ea883530fcc02203a80f8d843011b8ab0c9462dc46970c17ada4aae39d1e4fc0dc01b59522677bc4d6201645521020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db21026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a422103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d59ae67020001b275512102199fa8ade567942c1c07a44ac4e449f0bda515d41809a1e5d5997f39fcdb255c51ae68");


	/* Samples */
	std::cout << "\n\n";
	std::cout << "Sample P2PK\n";
	std::cout << "  scriptPuKey :: " << (scriptPubKey_sampleP2PK.size()) << "\n";
 	std::cout << "    IsStandard :: " << IsStandard(scriptPubKey_sampleP2PK, std::nullopt, which_type) << "\n";
	std::cout << "    IsPayToScriptHash :: " << scriptPubKey_sampleP2PK.IsPayToScriptHash() << "\n";
	check_type(which_type);
	std::cout << "\n";
	std::cout << "  scriptSig :: " << (scriptSig_sampleP2PK.size()) << "\n";
	std::cout << "    GetSigOpCount :: " << scriptSig_sampleP2PK.GetSigOpCount(scriptSig_sampleP2PK) << "\n";
	IsStandard(scriptSig_sampleP2PK, std::nullopt, which_type);
	check_type(which_type);

	std::cout << "\n";
	std::cout << "Sample P2PKH\n";
	std::cout << "  scriptPuKey :: " << (scriptPubKey_sampleP2PKH.size()) << "\n";
 	std::cout << "    IsStandard :: " << IsStandard(scriptPubKey_sampleP2PKH, std::nullopt, which_type) << "\n";
	std::cout << "    IsPayToScriptHash :: " << scriptPubKey_sampleP2PKH.IsPayToScriptHash() << "\n";
	check_type(which_type);
	std::cout << "\n";
	std::cout << "  scriptSig :: " << (scriptSig_sampleP2PKH.size()) << "\n";
	std::cout << "    GetSigOpCount :: " << scriptPubKey_sampleP2PKH.GetSigOpCount(scriptSig_sampleP2PKH) << "\n";
	IsStandard(scriptSig_sampleP2PKH, std::nullopt, which_type);
	check_type(which_type);

	std::cout << "\n";
	std::cout << "Sample P2SH\n";
	std::cout << "  scriptPuKey :: " << (scriptPubKey_sampleP2SH.size()) << "\n";
 	std::cout << "    IsStandard :: " << IsStandard(scriptPubKey_sampleP2SH, std::nullopt, which_type) << "\n";
	std::cout << "    IsPayToScriptHash :: " << scriptPubKey_sampleP2SH.IsPayToScriptHash() << "\n";
	check_type(which_type);
	std::cout << "\n";
	std::cout << "  scriptSig :: " << (scriptSig_sampleP2SH.size()) << "\n";
	std::cout << "    GetSigOpCount :: " << scriptPubKey_sampleP2SH.GetSigOpCount(scriptSig_sampleP2SH) << "\n";
	IsStandard(scriptSig_sampleP2SH, std::nullopt, which_type);
	check_type(which_type);

	/* ERP */
	std::cout << "\n";
	std::cout << "Deprecate ERP\n";
	std::cout << "  scriptPuKey :: " << (scriptPubKey_deprecateERP.size()) << "\n";
 	std::cout << "    IsStandard :: " << IsStandard(scriptPubKey_deprecateERP, std::nullopt, which_type) << "\n";
	std::cout << "    IsPayToScriptHash :: " << scriptPubKey_deprecateERP.IsPayToScriptHash() << "\n";
	check_type(which_type);
	std::cout << "\n";
	std::cout << "  scriptSig :: " << (scriptSig_deprecateERP.size()) << "\n";
	std::cout << "    GetSigOpCount :: " << scriptPubKey_deprecateERP.GetSigOpCount(scriptSig_deprecateERP) << "\n";
	std::cout << "    AreInputsStandard::GetSigOpCount(true) > MAX_P2SH_SIGOPS :: 1" << "\n";
	check_type(which_type);
	
	assert(scriptPubKey_deprecateERP.GetSigOpCount(scriptSig_deprecateERP) > MAX_P2SH_SIGOPS);

	std::cout << "\n";
	std::cout << "New ERP\n";
	std::cout << "  scriptPuKey :: " << (scriptPubKey_newERP.size()) << "\n";
 	std::cout << "    IsStandard :: " << IsStandard(scriptPubKey_newERP, std::nullopt, which_type) << "\n";
	std::cout << "    IsPayToScriptHash :: " << scriptPubKey_newERP.IsPayToScriptHash() << "\n";
	check_type(which_type);
	std::cout << "\n";
	std::cout << "  scriptSig :: " << (scriptSig_newERP.size()) << "\n";
	std::cout << "    GetSigOpCount :: " << scriptPubKey_newERP.GetSigOpCount(scriptSig_newERP) << "\n";
	std::cout << "    AreInputsStandard::GetSigOpCount(true) > MAX_P2SH_SIGOPS :: 0" << "\n";
	check_type(which_type);
	std::cout << "\n\n";

	assert(scriptPubKey_newERP.GetSigOpCount(scriptSig_newERP) < MAX_P2SH_SIGOPS);
#endif

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
