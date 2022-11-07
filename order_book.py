from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from models import Base, Order

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def process_order(order):
    # Your code here
    sender_pk = order['sender_pk']
    receiver_pk = order['receiver_pk']
    buy_currency = order['buy_currency']
    sell_currency = order['sell_currency']
    buy_amount = order['buy_amount']
    sell_amount = order['sell_amount']

    new_order = Order(sender_pk=sender_pk, receiver_pk=receiver_pk, buy_currency=buy_currency,
                      sell_currency=sell_currency, buy_amount=buy_amount, sell_amount=sell_amount, filled=None)

    session.add(new_order)
    session.commit()

    for existing_order in session.query(Order).filter(Order.creator is None).all():
        if existing_order.filled is not None or existing_order.buy_currency != new_order.sell_currency or existing_order.sell_currency != new_order.buy_currency or existing_order.sell_amount / existing_order.buy_amount < new_order.buy_amount / new_order.sell_amount:
            continue

        timestamp: datetime = datetime.now()
        new_order.filled = timestamp
        existing_order.filled = timestamp

        existing_order.counterparty_id = new_order.id
        new_order.counterparty_id = existing_order.id
        session.commit()

        if new_order.sell_amount > existing_order.buy_amount:
            child_buy_amount = (
                                           new_order.sell_amount - existing_order.buy_amount) * new_order.buy_amount / new_order.sell_amount
            child_sell_amount = new_order.sell_amount - existing_order.buy_amount
            order_child_creator_id = new_order.id
            # add updated fields to child order
            child_order = Order(sender_pk=sender_pk,
                                receiver_pk=receiver_pk,
                                buy_currency=buy_currency,
                                sell_currency=sell_currency,
                                buy_amount=child_buy_amount,
                                sell_amount=child_sell_amount,
                                creator_id=order_child_creator_id,
                                filled=None)
            session.add(child_order)
            session.commit()

        elif new_order.sell_amount < existing_order.buy_amount:
            child_sender_pk = existing_order.sender_pk
            child_receiver_pk = existing_order.receiver_pk
            child_buy_currency = existing_order.buy_currency
            child_sell_currency = existing_order.sell_currency
            child_buy_amount = (existing_order.buy_amount - new_order.sell_amount)
            child_sell_amount = (existing_order.buy_amount - new_order.sell_amount) * (
                        existing_order.sell_amount / existing_order.buy_amount)
            order_child_creator_id = existing_order.id

            child_order = Order(sender_pk=child_sender_pk,
                                receiver_pk=child_receiver_pk,
                                buy_currency=child_buy_currency,
                                sell_currency=child_sell_currency,
                                buy_amount=child_buy_amount,
                                sell_amount=child_sell_amount,
                                creator_id=order_child_creator_id,
                                filled=None)

            session.add(child_order)
            session.commit()

        break

        return