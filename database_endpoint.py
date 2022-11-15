from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine, select, MetaData, Table
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only

from models import Base, Order, Log

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)


# These decorators allow you to use g.session to access the database inside the request code
@app.before_request
def create_session():
    g.session = scoped_session(
        DBSession)  # g is an "application global" https://flask.palletsprojects.com/en/1.1.x/api/#application-globals


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    g.session.commit()
    g.session.remove()


"""
-------- Helper methods (feel free to add your own!) -------
"""


def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    log = Log(message = json.dumps(d))
    g.session.add(log)
    g.session.commit
    #pass


#def validate(content):
"""
---------------- Endpoints ----------------
"""


@app.route('/trade', methods=['POST'])
def trade():
    if request.method == "POST":
        content = request.get_json(silent=True)
        print(f"content = {json.dumps(content)}")
        columns = ["sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                print(json.dumps(content))
                log_message(content)
                return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            log_message(content)
            return jsonify(False)

        # Your code here
        # Note that you can access the database session using g.session
        signature = content['sig']
        payload = json.dumps(content['payload'])
        payload_contents = content['payload']
        sender_pk = payload_contents['sender_pk']
        receiver_pk = payload_contents['receiver_pk']
        buy_currency = payload_contents['buy_currency']
        sell_currency: object = payload_contents['sell_currency']
        buy_amount = payload_contents['buy_amount']
        sell_amount = payload_contents['sell_amount']
        platform = payload_contents['platform']

        #conditions below
        if platform == 'Ethereum':
            eth_encoded_msg = eth_account.messages.encode_defunct(text = payload)
            if eth_account.Account.recover_message(eth_encoded_msg, signature=signature) == sender_pk:
                current_order = Order(sender_pk = sender_pk,
                                      receiver_pk = receiver_pk,
                                      buy_currency = buy_currency,
                                      sell_currency = sell_currency,
                                      buy_amount = buy_amount,
                                      sell_amount = sell_amount,
                                      signature = signature)
                g.session.add(current_order)
                g.session.commit()
                return jsonify(True)
            else:
                log_message(content)
                return jsonify(False)
        elif platform == 'Algorand':
            if algosdk.util.verify_bytes(payload.encode('utf-8'), signature, sender_pk):
                print('Algorand signature validated.')
                current_order = Order(sender_pk = sender_pk,
                                      receiver_pk = receiver_pk,
                                      buy_currency = buy_currency,
                                      sell_currency = sell_currency,
                                      buy_amount = buy_amount,
                                      sell_amount = sell_amount,
                                      signature = signature)
                g.session.add(current_order)
                g.session.commit()
                return jsonify(True)
            else:
                log_message(content)
                return jsonify(False)


@app.route('/order_book')
def order_book():
    # Your code here
    # Note that you can access the database session using g.session
    session_orders = g.session.query(Order).filter().all()
    # initialize the list to store values here
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
