import argparse
from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from datetime import timedelta
import os

from .middleware import DetectionMiddleware

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('FLASK_SECRET', 'devsecret')
app.permanent_session_lifetime = timedelta(hours=2)

# Simple in-memory catalog
PRODUCTS = {
    1: {"id": 1, "name": "Nimbus Tee", "price": 19.99, "img": "https://picsum.photos/seed/tee/400/280"},
    2: {"id": 2, "name": "Storm Jacket", "price": 89.0, "img": "https://picsum.photos/seed/jacket/400/280"},
    3: {"id": 3, "name": "Cloud Cap", "price": 14.5, "img": "https://picsum.photos/seed/cap/400/280"},
}


@app.before_request
def _before():
    if getattr(app, 'detector_mw', None):
        app.detector_mw.before()


@app.after_request
def _after(response):
    if getattr(app, 'detector_mw', None):
        return app.detector_mw.after(response)
    return response


@app.route('/')
def home():
    return render_template('index.html', products=list(PRODUCTS.values()), title='Nimbus Shop')


@app.route('/product/<int:pid>', methods=['GET'])
def product(pid: int):
    p = PRODUCTS.get(pid)
    if not p:
        return jsonify({"error": "not found"}), 404
    return render_template('product.html', product=p, title=p['name'])


@app.route('/cart', methods=['GET', 'POST'])
def cart():
    session.permanent = True
    cart = session.get('cart', {})
    if request.method == 'POST':
        pid = int(request.form.get('pid', '0'))
        if pid in PRODUCTS:
            cart[str(pid)] = cart.get(str(pid), 0) + 1
            session['cart'] = cart
        return redirect(url_for('cart'))
    # compute totals
    items = []
    total = 0.0
    for k, qty in cart.items():
        p = PRODUCTS.get(int(k))
        if p:
            line = {"product": p, "qty": qty, "line": round(p['price'] * qty, 2)}
            total += line['line']
            items.append(line)
    return render_template('cart.html', items=items, total=round(total, 2), title='Your Cart')


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        session['cart'] = {}
        return render_template('checkout.html', ok=True, title='Checkout')
    return render_template('checkout.html', ok=False, title='Checkout')


@app.route('/login', methods=['POST'])
def login():
    return jsonify({"status": "ok"})


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--auto_mitigation', type=lambda x: str(x).lower() == 'true', default=False)
    parser.add_argument('--host', type=str, default='127.0.0.1')
    parser.add_argument('--conf_threshold', type=float, default=0.5)
    args = parser.parse_args()
    # attach middleware
    app.detector_mw = DetectionMiddleware(
        app,
        auto_mitigation=args.auto_mitigation,
        conf_threshold=args.conf_threshold,
    )
    app.run(host=args.host, port=args.port)


if __name__ == '__main__':
    main()
