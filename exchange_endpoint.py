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
import sys

from models import Base, Order, Log

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)


@app.before_request
def create_session():
    g.session = scoped_session(DBSession)


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


""" Suggested helper methods """


def check_sig(payload, sig):
    pass


def fill_order(order, txes=[]):
    pass


def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    log = Log(message=json.dumps(d))
    g.session.add(log)
    g.session.commit
    # pass


""" End of helper methods """


def process_order(order):
    # Your code here
    session = g.session
    new_order = order
    session.add(new_order)
    session.commit

    for existing_order in session.query(Order).filter(Order.filled == None).all():
        if (existing_order.filled is not None or existing_order.buy_currency != new_order.sell_currency or \
                existing_order.sell_currency != new_order.buy_currency or \
                existing_order.sell_amount / existing_order.buy_amount < new_order.buy_amount / new_order.sell_amount):
            continue

        timestamp: datetime = datetime.now()
        new_order.filled = timestamp
        existing_order.filled = timestamp
        existing_order.counterparty_id = new_order.id
        new_order.counterparty_id = existing_order.id
        session.commit

        if existing_order.sell_amount > new_order.buy_amount:
            child_sell_amount = (existing_order.sell_amount - new_order.buy_amount)
            child_buy_amount = child_sell_amount/(existing_order.sell_amount / existing_order.buy_amount)
            order_child_creator_id = existing_order.id
            # add updated fields to child order
            child_order = Order(sender_pk=existing_order.sender_pk,
                                receiver_pk=existing_order.receiver_pk,
                                buy_currency=existing_order.buy_currency,
                                sell_currency=existing_order.sell_currency,
                                buy_amount=child_buy_amount,
                                sell_amount=child_sell_amount,
                                creator_id=order_child_creator_id,
                                filled=None)
            session.add(child_order)
            session.commit

        elif new_order.buy_amount > existing_order.sell_amount:
            child_buy_amount = (new_order.buy_amount - existing_order.sell_amount)
            child_sell_amount = child_buy_amount / (new_order.buy_amount / new_order.sell_amount)
            order_child_creator_id = new_order.id
            child_order = Order(sender_pk=new_order.sender_pk,
                                receiver_pk=new_order.receiver_pk,
                                buy_currency=new_order.buy_currency,
                                sell_currency=new_order.sell_currency,
                                buy_amount=child_buy_amount,
                                sell_amount=child_sell_amount,
                                creator_id=order_child_creator_id,
                                filled=None)

            session.add(child_order)
            session.commit

        break
    return


@app.route('/trade', methods=['POST'])
def trade():
    print("In trade endpoint")
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = ["sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform"]
        fields = ["sig", "payload"]

        for field in fields:
            if not field in content.keys():
                log_message(content)
                return jsonify(False)

        for column in columns:
            if not column in content['payload'].keys():
                log_message(content)
                return jsonify(False)

        # Your code here
        # Note that you can access the database session using g.session
        signature = content['sig']
        payload = json.dumps(content['payload'])
        payload_contents = content['payload']
        sender_pk = content['payload']['sender_pk']
        receiver_pk = content['payload']['receiver_pk']
        buy_currency = content['payload']['buy_currency']
        sell_currency: object = content['payload']['sell_currency']
        buy_amount = content['payload']['buy_amount']
        sell_amount = content['payload']['sell_amount']
        platform = content['payload']['platform']

        if platform == 'Ethereum':
            eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
            if eth_account.Account.recover_message(eth_encoded_msg, signature=signature) == sender_pk:
                process_order(Order(sender_pk=sender_pk, receiver_pk=receiver_pk, buy_currency=buy_currency,
                                    sell_currency=sell_currency, buy_amount=buy_amount, sell_amount=sell_amount,
                                    signature=signature))

                return jsonify(True)
            else:
                log_message(content)
                return jsonify(False)
        elif platform == 'Algorand':
            if algosdk.util.verify_bytes(payload.encode('utf-8'), signature, sender_pk):
                process_order(Order(sender_pk=sender_pk,
                                    receiver_pk=receiver_pk,
                                    buy_currency=buy_currency,
                                    sell_currency=sell_currency,
                                    buy_amount=buy_amount,
                                    sell_amount=sell_amount,
                                    signature=signature))
                return jsonify(True)
            else:
                log_message(content)
                return jsonify(False)
        else:
            print(f'Error: platform not recognized.')
            return jsonify("Error: platform not recognized.")

        # TODO: Check the signature

        # TODO: Add the order to the database

        # TODO: Fill the order

        # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful


@app.route('/order_book')
def order_book():
    # Your code here
    # Note that you can access the database session using g.session
    session_orders = g.session.query(Order).filter().all()
    empty_list = []

    for this_order in session_orders:
        order = {}
        assert isinstance(this_order.sender_pk, object)
        order['sender_pk'] = this_order.sender_pk
        order['receiver_pk'] = this_order.receiver_pk
        order['buy_currency'] = this_order.buy_currency
        assert isinstance(this_order.sell_currency, object)
        order['sell_currency'] = this_order.sell_currency
        assert isinstance(this_order.buy_amount, object)
        order['buy_amount'] = this_order.buy_amount
        order['sell_amount'] = this_order.sell_amount
        order['signature'] = this_order.signature
        empty_list.append(order)
    result = {'data': empty_list}

    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')
