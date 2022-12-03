from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from web3 import Web3
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth, wait_for_confirmation_algo
from models import Base, Order, TX, Log

w3 = connect_to_eth()
acl = connect_to_algo(connection_type="indexer")
bcl = connect_to_algo(connection_type="other")

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """


@app.before_request
def create_session():
    g.session = scoped_session(DBSession)


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


def connect_to_blockchains():
    try:
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True

    try:
        if acl_flag or not g.acl.status():
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()

    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True

    try:
        if icl_flag or not g.icl.health():
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True

    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()


""" End of pre-defined methods """

""" Helper Methods (skeleton code for you to implement) """


def log_message(d):
    log = Log(message=json.dumps(d), logtime=datetime.now())
    g.session.add(log)
    g.session.commit
    # pass


def get_algo_keys():
    # TODO: Generate or read (using the mnemonic secret)
    # the algorand public/private keys

    account_private_key = '17oAlM5JLwL/Yut2YtOdoSwFXoWVPJxu502fJgzZ3SPZFHaVuQnlRagViosxYUXWEGN68mdn0atoTTxH/cbSyg=='
    account_public_key = '3EKHNFNZBHSULKAVRKFTCYKF2YIGG6XSM5T5DK3IJU6EP7OG2LFI6QX6YY'

    algo_sk = account_private_key
    algo_pk = account_public_key

    return algo_sk, algo_pk


def get_eth_keys(filename="mnemonic.txt"):
    w3 = Web3()
    w3.eth.account.enable_unaudited_hdwallet_features()

    # with open(filename, 'r') as file:
    # mnemonic = file.read().strip()
    acct = w3.eth.account.from_mnemonic("frozen logic forum huge scan all intact betray genuine visit project guard drip kick make")

    eth_pk = acct.address
    eth_sk = acct.key

    return eth_sk, eth_pk


def fill_order(order):
    # TODO:
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!

    # create query to iterate through to find matches
    iterable_query = g.session.query(Order).filter(Order.filled == None).all()

    for order_to_match in iterable_query:
        if order_to_match.sell_currency == order.buy_currency and order_to_match.buy_currency == order.sell_currency:

            if order_to_match.sell_amount / order_to_match.buy_amount >= (order.buy_amount / order.sell_amount):
                # seems to generate an error as there may be a lag in fetching timestamp
                # timestamp = datetime.now()

                order.filled = datetime.now()
                order_to_match.filled = datetime.now()

                order.counterparty_id = order_to_match.id
                order_to_match.counterparty_id = order.id

                transaction_to_execute = [order, order_to_match]
                print('transaction ready for execution')
                execute_txes(transaction_to_execute)

                if order.buy_amount > order_to_match.sell_amount:
                    fractional_buy_amount = order.buy_amount - order_to_match.sell_amount

                    order_builder = Order(creator_id=order.id,
                                          counterparty_id=None,
                                          sender_pk=order.sender_pk,
                                          receiver_pk=order.receiver_pk,
                                          buy_currency=order.buy_currency,
                                          sell_currency=order.sell_currency,
                                          buy_amount=fractional_buy_amount,
                                          # built in math function seems to be unpredictable
                                          # in helping match fractional orders,
                                          # doing it the old fashioned way
                                          sell_amount=int(
                                              (fractional_buy_amount / (order.buy_amount / order.sell_amount)) +
                                              ((fractional_buy_amount % (order.buy_amount / order.sell_amount)) != 0)),
                                          filled=None)
                    g.session.add(order_builder)

                elif order_to_match.buy_amount > order.sell_amount:
                    fractional_buy_amount = order_to_match.buy_amount - order.sell_amount

                    assert isinstance(order_to_match.sell_currency, object)
                    order_builder = Order(creator_id=order_to_match.id,
                                          counterparty_id=None,
                                          sender_pk=order_to_match.sender_pk,
                                          receiver_pk=order_to_match.receiver_pk,
                                          buy_currency=order_to_match.buy_currency,
                                          sell_currency=order_to_match.sell_currency,
                                          buy_amount=fractional_buy_amount,
                                          sell_amount=ceiling(
                                              fractional_buy_amount * (
                                                      order_to_match.sell_amount / order_to_match.buy_amount)),
                                          filled=None)
                    g.session.add(order_builder)
                g.session.commit()
                break


def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print(f"Trying to execute {len(txes)} transactions")

    algo_sk, algo_pk = get_algo_keys()
    eth_sk, eth_pk = get_eth_keys()

    if not all(tx.sell_currency in ["Algorand", "Ethereum"] for tx in txes):
        print("Error: execute_txes got an invalid platform!")
        print(tx.sell_currency for tx in txes)
    # initialize empty list to hold pairs
    matched_tx_pairs = []

    # grab index 0 of input list as first of pair
    order = txes[0]
    matching_order = txes[1]

    def min_no_math(a, b):
        if a > b:
            return b
        else:
            return a

    matched_pair_first = {
        'platform': matching_order.buy_currency,
        # initialize tx_id to 0,
        # return value for underlying method in send_tokens.py
        # will return the transaction hash as a HexBytes object.
        'tx_id': 0,
        'receiver_pk': matching_order.receiver_pk,
        'order_id': matching_order.id,
        'send_amount': min_no_math(order.sell_amount, matching_order.buy_amount)
    }
    matched_tx_pairs.append(matched_pair_first)

    matched_pair_second = {
        'tx_id': 0,
        'platform': order.buy_currency,
        'receiver_pk': order.receiver_pk,
        'order_id': order.id,
        'send_amount': min_no_math(order.buy_amount, matching_order.sell_amount)
    }
    matched_tx_pairs.append(matched_pair_second)
    # subset matched transactions by platform type
    matched_ethereum_transactions = [tx for tx in matched_tx_pairs if tx['platform'] == "Ethereum"]
    matched_algorand_transactions = [tx for tx in matched_tx_pairs if tx['platform'] == "Algorand"]

    eth_zero_index = matched_ethereum_transactions[0]
    ethereum_txes_to_commit = TX(platform=eth_zero_index['platform'],
                                 order_id=eth_zero_index['order_id'],
                                 receiver_pk=eth_zero_index['receiver_pk'],
                                 tx_id=send_tokens_eth(w3, eth_sk, matched_ethereum_transactions))

    g.session.add(ethereum_txes_to_commit)
    g.session.commit()

    algo_zero_index = matched_algorand_transactions[0]
    algorand_txes_to_commit = TX(platform=algo_zero_index['platform'],
                                 receiver_pk=algo_zero_index['receiver_pk'],
                                 order_id=algo_zero_index['order_id'],
                                 tx_id=send_tokens_algo(bcl, algo_sk, matched_algorand_transactions))

    g.session.add(algorand_txes_to_commit)
    g.session.commit()


# adding helper method to validate signatures which was handled
# internally within fill order function in IV
def validate_signature(payload, sig):
    sender_pk = payload['sender_pk']
    platform = payload['platform']
    payload = json.dumps(payload)
    if platform == 'Ethereum':
        msg_e = eth_account.messages.encode_defunct(text=payload)
        if eth_account.Account.recover_message(msg_e, signature=sig) == sender_pk:
            return True
    elif platform == 'Algorand':
        if algosdk.util.verify_bytes(payload.encode('utf-8'), sig, sender_pk):
            return True
    return False


# helper methods to avoid using built-in math methods,
# which seem to give unpredictable results in some cases
def perfect_division(a, b):
    val = int((a / b) + ((a % b) != 0))
    return val


def ceiling(n):
    result = int(n)
    if result == n or n < 0:
        return result
    else:
        return result + 1


# need a helper method to validate transactions
# was getting error messages prior to introducing this method
def validate_eth_and_algo_transactions(payload, tx_to_validate):
    if tx_to_validate.sell_currency == "Ethereum":
        try:
            ethereum_transaction = w3.eth.get_transaction(payload['tx_id'])
        except Exception as e:
            print('error retrieving eth transaction')
            print(e)
            result = False
            return result
        if ethereum_transaction['from'] == payload['sender_pk'] and \
                ethereum_transaction['value'] == payload['sell_amount']:
            result = True
            print('Ethereum transaction validated')
            return result

    elif tx_to_validate.sell_currency == "Algorand":
        wait_for_confirmation_algo(connect_to_algo(), payload['tx_id'])
        try:
            algorand_transactions = acl.search_transactions(txid=payload['tx_id'])
        except Exception as e:
            print('error retrieving algo transaction')
            print(e)
            result = False
            return result

        for algo_tx in algorand_transactions['transactions']:
            if algo_tx['payment-transaction']['amount'] == payload['sell_amount'] and \
                    algo_tx['sender'] == payload['sender_pk']:
                result = True
                print('Algorand transaction validated')
                return result

    return False


""" End of Helper methods"""


@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print(f"Error: no platform provided")
            return jsonify("Error: no platform provided")
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print(f"Error: {content['platform']} is an invalid platform")
            return jsonify(f"Error: invalid platform provided: {content['platform']}")

        if content['platform'] == "Ethereum":
            # Your code here
            eth_sk, eth_pk = get_eth_keys()
            return jsonify(eth_pk)
        elif content['platform'] == "Algorand":
            algo_sk, algo_pk = get_algo_keys()
            return jsonify(algo_pk)


@app.route('/trade', methods=['POST'])
def trade():
    print("In trade", file=sys.stderr)
    connect_to_blockchains()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = ["buy_currency", "sell_currency", "buy_amount",
                   "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        payload = content['payload']
        sig = content['sig']
        is_validated = validate_signature(payload, sig)
        if is_validated:
            order_for_execution = Order(sender_pk=payload['sender_pk'],
                                        receiver_pk=payload['receiver_pk'],
                                        buy_currency=payload['buy_currency'],
                                        sell_currency=payload['sell_currency'],
                                        buy_amount=payload['buy_amount'],
                                        sell_amount=payload['sell_amount'],
                                        signature=sig,
                                        tx_id=payload['tx_id'])
            g.session.add(order_for_execution)
            g.session.commit()
            # call custom method to validate transactions here
            validated_transaction = validate_eth_and_algo_transactions(payload, order_for_execution)
            if not validated_transaction:
                print('unable to validate transaction')
                return jsonify(False)

            fill_order(order_for_execution)
            log_message(content)

        else:
            log_message(content)

        return jsonify(is_validated)


@app.route('/order_book')
def order_book():
    data = []

    for order in g.session.query(Order).all():
        data.append({
            'sender_pk': order.sender_pk,
            'receiver_pk': order.receiver_pk,
            'buy_currency': order.buy_currency,
            'sell_currency': order.sell_currency,
            'buy_amount': order.buy_amount,
            'sell_amount': order.sell_amount,
            'signature': order.signature,
            'tx_id': order.tx_id
        })
    return jsonify(data=data)


if __name__ == '__main__':
    app.run(port='5002')
