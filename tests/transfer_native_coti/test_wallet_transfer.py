import random

from coti_wallet.crypto_helper import *
from coti_wallet.node_actions import *
import logging

tx_manager_logger = logging.getLogger("tx_manager_logger")
modules_in_out_logger = logging.getLogger("modules_in_out")


def read_destination_addresses_from_file(destination_addresses_file_name):
    try:
        file1 = open(destination_addresses_file_name, 'r')
        lines = file1.readlines()

        return lines
    except Exception as e:
        raise e


def launch_transactions(full_node_backend_address, trust_score_backend_address, source_seed, source_address_index,
                        fee_included, transaction_description, currency_hash, amount, destination_addresses_file_name,
                        transaction_type):
    global successful_transactions
    global failed_transactions

    modules_in_out_logger.info("\t++++> launch_transactions start time: " + time.strftime("%H:%M:%S", time.localtime()))
    launch_transactions_start_time = int(datetime.datetime.now().timestamp())

    destination_addresses = read_destination_addresses_from_file(destination_addresses_file_name)
    destination_addresses_length = len(destination_addresses)
    if destination_addresses_length == 0:
        raise ValueError('You have to specify at least one destination address!')

    for i in (range(destination_addresses_length)):
        user_private_key, source_address_public_key, source_address_public_key_crc, address_private = \
            KeyAndAddressFromSeed(bytearray.fromhex(str(source_seed)), source_address_index)
        source_address_balance = get_account_balance(source_address_public_key_crc, full_node_backend_address)

        if source_address_balance < float(amount):
            raise ValueError(
                'Not enough funds (' + str(amount) + ') in source address (' + str(source_address_balance) + ') !')

        destination_address = destination_addresses[i]
        destination_address = destination_address.translate(mapping)
        full_node_fee, input_base_transaction, instant_time, instant_time1, network_fee_data, private_key, \
            public_key, receiver_base_transaction, transaction_description, transaction_hash, \
            transaction_trust_score_data = \
            call_apis_to_prepare_a_tx(source_address_public_key_crc, destination_address, amount, currency_hash,
                                      source_seed, address_private, transaction_description, full_node_backend_address,
                                      trust_score_backend_address, fee_included)

        transaction_creation_result = create_transaction(full_node_backend_address, full_node_fee,
                                                         input_base_transaction,
                                                         instant_time,
                                                         instant_time1,
                                                         network_fee_data, private_key, public_key,
                                                         receiver_base_transaction,
                                                         transaction_description, transaction_hash,
                                                         transaction_trust_score_data, transaction_type)

        if transaction_creation_result['status'] == 'Success':
            successful_transactions += 1
        else:
            failed_transactions += 1

    tx_manager_logger.info("\t---> Successful Transactions  : " + str(successful_transactions))
    tx_manager_logger.info("\t---> Failed Transactions      : " + str(failed_transactions))
    modules_in_out_logger.info("\t++++> launch_transactions took: "
                               + str(int(datetime.datetime.now().timestamp()) - launch_transactions_start_time)
                               + " sec <++++")


def get_nodes(node_manager_address):
    nodes = get_nodes_details(node_manager_address)
    number_of_trust_score_nodes = len(nodes['TrustScoreNodes'])
    if number_of_trust_score_nodes == 0:
        raise Exception('no trust score server found!')
    else:
        selected_trust_score_node_index = random.randint(0, number_of_trust_score_nodes - 1)
        trust_score_node = nodes['TrustScoreNodes'][selected_trust_score_node_index]

    number_of_full_nodes = len(nodes['FullNodes'])
    if number_of_full_nodes == 0:
        raise Exception('no full nodes found!')
    else:
        selected_full_node_index = random.randint(0, number_of_full_nodes - 1)
        full_node = nodes['FullNodes'][selected_full_node_index]

    number_of_financial_server = len(nodes['FinancialServer'])
    if number_of_financial_server == 0:
        raise Exception('no financial server found!')
    else:
        financial_server = nodes['FinancialServer'][0]

    return trust_score_node, full_node, financial_server


def read_env_file():
    env_details = {}
    with open(".env") as env_file:
        for line in env_file:
            name, var = line.partition("=")[::2]
            env_details[name.strip()] = var

    node_manager_address = str(env_details.get('NODE_MANAGER_ADDRESS')).translate(mapping)
    full_node_backend_address = str(env_details.get('FULL_NODE_BACKEND_ADDRESS')).translate(mapping)
    trust_score_backend_address = str(env_details.get('TRUST_SCORE_BACKEND_ADDRESS')).translate(mapping)
    source_seed = str(env_details.get('SOURCE_SEED')).translate(mapping)
    assert source_seed != ''
    source_address_index = int(env_details.get('SOURCE_ADDRESS_INDEX'))
    fee_included = str(env_details.get('FEE_INCLUDED')).lower() in ['true']
    transaction_description = str(env_details.get('TRANSACTION_DESCRIPTION')).translate(mapping)
    currency_hash = str(env_details.get('CURRENCY_HASH')).translate(mapping)
    amount = str(env_details.get('AMOUNT')).translate(mapping)
    logging_module_in_out = str(env_details.get('LOGGING_MODULE_IN_OUT')).translate(mapping).lower() in ['true']
    logging_api_call_times = str(env_details.get('LOGGING_API_CALL_TIMES')).translate(mapping).lower() in ['true']
    destination_addresses_file_name = env_details.get('DESTINATION_ADDRESSES_FILE_NAME').translate(mapping)
    transaction_type = env_details.get('TRANSACTION_TYPE').translate(mapping)

    return node_manager_address, full_node_backend_address, trust_score_backend_address, source_seed, \
        source_address_index, fee_included, transaction_description, currency_hash, amount, logging_module_in_out, \
        logging_api_call_times, destination_addresses_file_name, transaction_type


def main():
    node_manager_address, full_node_address, trust_score_address, source_seed, source_address_index, fee_included, \
        transaction_description, currency_hash, amount, logging_module_in_out, logging_api_call_times, \
        destination_addresses_file_name, transaction_type = read_env_file()

    if not str(node_manager_address) == 'None':
        trust_score_node, full_node, financial_server = get_nodes(node_manager_address)
        trust_score_address = trust_score_node['url']
        full_node_address = full_node['url']
        financial_server_address = financial_server['url']
        tx_manager_logger.info("fullnode: " + full_node_address + ", trustscore:" + trust_score_address)

    launch_transactions(full_node_address, trust_score_address, source_seed, source_address_index,
                        fee_included, transaction_description, currency_hash, amount, destination_addresses_file_name,
                        transaction_type)


mapping = dict.fromkeys(range(32))
successful_transactions = 0
failed_transactions = 0

main()
