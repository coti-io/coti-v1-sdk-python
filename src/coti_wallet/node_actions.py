import json
import time
import datetime
from decimal import getcontext, Decimal

from coti_wallet.crypto_helper import HashAndSign, PrivateKeyFromSeed, PublicKeyFromPrivateKey, \
    HashKeccak256, SignDigest
from coti_wallet.base import http_pool_manager, api_call_times_logger

http_ok_codes = [200, 201]


def init_context():
    cont = getcontext()
    cont.prec = 12
    cont.Emax = 999999999
    cont.Emin = -999999999
    return cont


def get_nodes_details(node_manager_address):
    start_time = time.time()

    headers = {'Content-Type': "application/json"}
    res = http_pool_manager.request('GET', node_manager_address + "/wallet/nodes", headers=headers)

    if res.status not in http_ok_codes:
        raise Exception('error return code: ' + str(res.status) + ', data: ' + str(res.data))

    data = json.loads(res.data.decode("utf-8"))
    if dict(data).get('status') == 'Error':
        raise Exception(data)

    api_call_times_logger.info("\t\t---> get_nodes_details: %s seconds ---" % round((time.time() - start_time), 3))

    return data.get('nodes')


def get_account_balance(address_id, full_node_address):
    start_time = time.time()

    payload = "{\n\"addresses\": [\"" + address_id + "\"]\n}\n"
    headers = {'Content-Type': "application/json"}
    res = http_pool_manager.request("POST", full_node_address + "/balance", body=payload, headers=headers)

    if res.status not in http_ok_codes:
        raise Exception('error return code: ' + str(res.status) + ', data: ' + str(res.data))

    data = json.loads(res.data.decode("utf-8"))
    if dict(data).get('status') == 'Error':
        raise Exception(data)

    api_call_times_logger.info("\t\t---> get_account_balance: %s seconds ---" % round((time.time() - start_time), 3))

    return data["addressesBalance"][address_id]["addressBalance"]


def create_full_node_fee(full_node_address, user_hash, private_key, original_currency_hash, amount, fee_included):
    start_time = time.time()

    original_amount = amount

    fnf_req_msg = bytes.fromhex(original_currency_hash) + original_amount.encode()
    signed_fnf_req_msg, _ = HashAndSign(bytearray.fromhex(private_key), fnf_req_msg)
    signature_data = {"r": signed_fnf_req_msg[0], "s": signed_fnf_req_msg[1]}

    body = {
        "originalAmount": original_amount,
        "feeIncluded": fee_included,
        "originalCurrencyHash": original_currency_hash,
        "currencyHash": original_currency_hash,
        "userHash": user_hash,
        "userSignature": signature_data
    }

    headers = {'Content-Type': "application/json"}
    res = http_pool_manager.request('PUT', full_node_address + "/fee", body=json.dumps(body), headers=headers)
    
    if res.status not in http_ok_codes:
        raise Exception('error return code: ' + str(res.status) + ', data: ' + str(res.data))

    data = json.loads(res.data.decode("utf-8"))
    if data.get('status') == 'Error':
        raise Exception(data)

    api_call_times_logger.info("\t\t---> create_full_node_fee: %s seconds <---" % round((time.time() - start_time), 3))

    return data['fullNodeFee']


def validate_network_fee(trust_score_address, user_hash, full_node_fee, network_fee_data):
    start_time = time.time()

    headers = {'Content-Type': "application/json"}
    network_fee_request = {"fullNodeFeeData": full_node_fee, "networkFeeData": network_fee_data, "userHash": user_hash}

    res = http_pool_manager.request('POST', trust_score_address + "/networkFee", body=json.dumps(network_fee_request),
                                    headers=headers)

    if res.status not in http_ok_codes:
        raise Exception('error return code: ' + str(res.status) + ', data: ' + str(res.data))

    data = json.loads(res.data.decode("utf-8"))
    if data.get('status') == 'Error':
        raise Exception(data)

    api_call_times_logger.info("\t\t---> validate_network_fee: %s seconds <---" % round((time.time() - start_time), 3))

    return data['networkFeeData']


def create_network_fee(trust_score_address, public_key, full_node_fee):
    start_time = time.time()

    headers = {'Content-Type': "application/json"}
    create_network_fee_request = {"fullNodeFeeData": full_node_fee, "userHash": public_key}
    res = http_pool_manager.request('PUT', trust_score_address + "/networkFee",
                                    body=json.dumps(create_network_fee_request), headers=headers)

    if res.status not in http_ok_codes:
        raise Exception('error return code: ' + str(res.status) + ', data: ' + str(res.data))

    data = json.loads(res.data.decode("utf-8"))
    if data.get('status') == 'Error':
        raise Exception(data)

    api_call_times_logger.info("\t\t---> create_network_fee: %s seconds <---" % round((time.time() - start_time), 3))

    return data['networkFeeData']


def build_receiver_base_transaction(instant_time, instant_time_millisecond, amount, currency_hash, destination_address):
    start_time = time.time()

    receiver_base_transaction = {"addressHash": destination_address, "amount": amount, "originalAmount": amount,
                                 "createTime": instant_time, "name": "RBT", "currencyHash": currency_hash,
                                 "originalCurrencyHash": currency_hash}
    msg_bytes = bytearray.fromhex(receiver_base_transaction["addressHash"]) \
        + str(receiver_base_transaction["amount"]).encode() \
        + instant_time_millisecond.to_bytes(8, byteorder='big') \
        + bytes.fromhex(currency_hash) \
        + str(receiver_base_transaction["originalAmount"]).encode() \
        + bytes.fromhex(currency_hash)
    msg_hash = HashKeccak256(msg_bytes)
    receiver_base_transaction["hash"] = msg_hash

    api_call_times_logger.info(
        "\t\t---> build_receiver_base_transaction: %s seconds <---" % round((time.time() - start_time), 3))

    return receiver_base_transaction


def get_trust_score_data(trust_score_address, public_key, private_key, transaction_hash):
    start_time = time.time()

    signed_transaction_hash = SignDigest(bytearray.fromhex(private_key), bytearray.fromhex(transaction_hash))
    body = {
        "userHash": public_key,
        "transactionHash": transaction_hash,
        "userSignature": {"r": signed_transaction_hash[0], "s": signed_transaction_hash[1]}
    }
    headers = {'Content-Type': "application/json"}
    res = http_pool_manager.request('POST', trust_score_address + "/transactiontrustscore",
                                    body=json.dumps(body), headers=headers)
    if res.status not in http_ok_codes:
        raise Exception('error return code: ' + str(res.status) + ', data: ' + str(res.data))

    data = json.loads(res.data.decode("utf-8"))
    if data.get('status') == 'Error':
        raise Exception(data)

    api_call_times_logger.info("\t\t---> get_trust_score_data: %s seconds <---" % round((time.time() - start_time), 3))

    return data['transactionTrustScoreData']


def create_input_base_transaction(address_private, currency_hash, full_node_fee,
                                  instant_time, instant_time_millisecond, network_fee_data,
                                  receiver_base_transaction, source_address, context):
    start_time = time.time()

    if currency_hash is None:
        currency_hash = full_node_fee["currencyHash"]

    full_amount = (
            Decimal(full_node_fee['originalAmount']) + Decimal(full_node_fee['amount']) +
            Decimal(network_fee_data['amount'])).normalize(context)
    input_base_transaction_amount = format(-full_amount, "f")
    ibt_msg = bytearray.fromhex(source_address) \
        + str(input_base_transaction_amount).encode() \
        + instant_time_millisecond.to_bytes(8, byteorder='big') + bytearray.fromhex(currency_hash)
    ibt_hash = HashKeccak256(ibt_msg)
    transaction_hash_bytes = ibt_hash + full_node_fee["hash"] + network_fee_data["hash"] \
        + receiver_base_transaction["hash"]
    transaction_hash = HashKeccak256(bytearray.fromhex(transaction_hash_bytes))
    address_signed_transaction_hash = SignDigest(bytearray.fromhex(address_private),
                                                 bytearray.fromhex(transaction_hash))
    ibt_signature_data = {"r": address_signed_transaction_hash[0], "s": address_signed_transaction_hash[1]}

    ibt = {
        "hash": ibt_hash,
        "amount": input_base_transaction_amount,
        "createTime": instant_time,
        "currencyHash": currency_hash,
        "addressHash": source_address,
        "name": "IBT",
        "signatureData": ibt_signature_data
    }

    api_call_times_logger.info(
        "\t\t---> create_input_base_transaction: %s seconds <---" % round((time.time() - start_time), 3))

    return ibt, transaction_hash


def call_apis_to_prepare_a_tx(source_address_public_key_crc, destination_address, amount, currency_hash, seed,
                              address_private, transaction_description, full_node_address, trust_score_address,
                              fee_included):
    start_time = time.time()

    instant_time = int(datetime.datetime.now().timestamp())
    instant_time_millisecond = instant_time * 1000

    context = init_context()

    private_key = PrivateKeyFromSeed(bytearray.fromhex(str(seed)))
    public_key, _ = PublicKeyFromPrivateKey(bytearray.fromhex(str(private_key)))

    full_node_fee = create_full_node_fee(full_node_address, public_key, private_key, currency_hash, amount,
                                         fee_included)
    create_network_fee_response = create_network_fee(trust_score_address, public_key, full_node_fee)
    validate_network_fee_1st_response = validate_network_fee(trust_score_address, public_key, full_node_fee,
                                                             create_network_fee_response)
    network_fee_data = validate_network_fee(trust_score_address, public_key, full_node_fee,
                                            validate_network_fee_1st_response)

    receiver_base_transaction = build_receiver_base_transaction(instant_time, instant_time_millisecond, amount, 
                                                                currency_hash, destination_address)

    input_base_transaction, transaction_hash = create_input_base_transaction(
        address_private, currency_hash, full_node_fee,
        instant_time, instant_time_millisecond,
        network_fee_data,
        receiver_base_transaction, source_address_public_key_crc, context)

    transaction_trust_score_data = get_trust_score_data(trust_score_address, public_key, private_key,
                                                        transaction_hash)

    api_call_times_logger.info(
        "\t\t---> call_apis_to_prepare_a_tx : %s seconds <---" % round((time.time() - start_time), 3))

    return full_node_fee, input_base_transaction, instant_time, instant_time_millisecond, network_fee_data, \
        private_key, public_key, receiver_base_transaction, transaction_description, transaction_hash, \
        transaction_trust_score_data


def create_transaction(full_node_address, full_node_fee, input_base_transaction, instant_time, instant_time_millisecond,
                       network_fee_data,
                       private_key, public_key, receiver_base_transaction, transaction_description, transaction_hash,
                       transaction_trust_score_data, transaction_type):
    start_time = time.time()

    base_transaction = [input_base_transaction, full_node_fee, network_fee_data, receiver_base_transaction]
    tx_bytes = bytearray.fromhex(transaction_hash) \
        + str(transaction_type).encode() \
        + instant_time_millisecond.to_bytes(8, byteorder='big') \
        + str(transaction_description).encode()
    st, _ = HashAndSign(bytearray.fromhex(private_key), tx_bytes)
    transaction_signature_data = {"r": st[0], "s": st[1]}
    body = {
        "hash": transaction_hash,
        "baseTransactions": base_transaction,
        "transactionDescription": transaction_description,
        "createTime": instant_time,
        "senderHash": public_key,
        "senderSignature": transaction_signature_data,
        "type": transaction_type,
        "trustScoreResults": [transaction_trust_score_data]
    }
    headers = {'Content-Type': "application/json"}

    res = http_pool_manager.request('PUT', full_node_address + "/transaction",
                                    body=json.dumps(body), headers=headers)
    if res.status not in http_ok_codes:
        raise Exception('error return code: ' + str(res.status) + ', data: ' + str(res.data))

    data = json.loads(res.data.decode("utf-8"))
    if data.get('status') == 'Error':
        raise Exception(data)

    api_call_times_logger.info("\t\t---> create_transaction: %s seconds <---" % round((time.time() - start_time), 3))

    return data
