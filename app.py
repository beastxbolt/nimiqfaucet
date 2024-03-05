from flask import Flask, make_response, request, redirect, session, render_template, url_for, send_file, flash
from flask_hcaptcha import hCaptcha
import os
import datetime
import random
import requests
import psycopg2
import hashlib
import numpy
import re

nimiq_api = os.environ["NIMIQ_API_KEY"]
nimiq_private_key = os.environ["NIMIQ_PRIVATE_KEY"]
hcaptcha_site_key = os.environ["HCAPTCHA_SITE_KEY"]
hcaptcha_secret_key = os.environ["HCAPTCHA_SECRET_KEY"]
database_url = os.environ["DATABASE_URL"]
bitswall_secret = os.environ["BITSWALL_SECRET"]

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = b'\xeb\xf9\xbe\x02\xcc\xff\r\xc2D\xf3\x04Vo\xf3}j'

hcaptcha = hCaptcha(app, hcaptcha_site_key, hcaptcha_secret_key, is_enabled=True)

try:
	db = psycopg2.connect(database_url)
	cursor = db.cursor()
	print("Database connected!")
except Exception as e:
	print(e)

def sendNimiq(address: str, amount: float = None):
	url = "https://api.nimiq.cafe/micro-tx/"
	
	if amount is None:
		value_nimtoshis = random.randint(10000, 15000)
	else:
		value_nimtoshis = int(numpy.float32(amount * 100000))

	data = {
		"api_key": nimiq_api,
		"from_private": nimiq_private_key,
		"to_address": address,
		"value_nimtoshis": value_nimtoshis,
		"fee_nimtoshis": 200
	}

	response = requests.post(url, data=data)

	hash = response.json()["hash"]
	session["value_nimtoshis"] = value_nimtoshis / 100000
	return hash

def clearsession():
	a = session.get("value_nimtoshis")
	if a is not None:
		del session["value_nimtoshis"]
	b = session.get("wallet_address")
	if b is not None:
		del session["wallet_address"]
	c = session.get("ip_address")
	if c is not None:
		del session["ip_address"]
	d = session.get("hash")
	if d is not None:
		del session["hash"]
	return

@app.errorhandler(404)
def not_found(e):
	clearsession()
	return render_template('404.html')

@app.errorhandler(500)
def not_found(e):
	return render_template('500.html')

@app.route('/')
def index():
	return render_template('home.html', title = 'Nimiq Faucet')

@app.route('/privacy')
def privacy():
	clearsession()
	return render_template('privacy.html', title = 'Privacy Policy | Nimiq Faucet')

@app.route('/disclaimer')
def disclaimer():
	clearsession()
	return render_template('disclaimer.html', title = 'Disclaimer | Nimiq Faucet')

@app.route('/contact')
def contact():
	clearsession()
	return render_template('contact.html', title = 'Contact Us | Nimiq Faucet')

@app.route('/donate')
def donate():
	clearsession()
	return render_template('donate.html', title = 'Donate | Nimiq Faucet')

@app.route('/offerwall')
def offerwall():
	offerwall_wallet_address = session.get("offerwall_wallet_address")
	if offerwall_wallet_address is None:
		is_wallet = False
	else:
		is_wallet = True

	return render_template('offerwall.html', title = 'Offerwall | Nimiq Faucet', is_wallet = is_wallet, session_wallet_address = offerwall_wallet_address)

@app.route('/offerwall/bitswall', methods=['GET'])
def bitswall():
	offerwall_wallet_address = session.get("offerwall_wallet_address")
	if offerwall_wallet_address is None:
		return redirect(url_for('offerwall'))
	else:
		return render_template('bitswall.html', title = 'Bitswall | Nimiq Faucet', session_wallet_address = offerwall_wallet_address)

@app.route('/bitswall-postback', methods=['POST', 'GET'])
def bitswall_postback():
	if request.method == 'POST':
		subId = request.form.get('subId')
		transId = str(request.form.get('transId'))
		reward = str(request.form.get("reward"))
		user_ip = str(request.form.get("userIp"))
		secret = bitswall_secret
		signature = request.form.get('signature')
		
		if hashlib.md5((subId + transId + reward + secret).encode()).hexdigest() != signature:
			return "ERROR: Signature doesn't match"
		else:
			cursor.execute("SELECT * FROM offerwall_transactions WHERE transaction_id = %s", (transId, ))
			tns = cursor.fetchone()
			if tns is None:
				hash = sendNimiq(subId, float(reward))
				current_datetime = str(datetime.datetime.utcnow().replace(microsecond=0))
				cursor.execute("INSERT INTO offerwall_transactions (offerwall_name, transaction_id, amount, hash, ip_address, datetime) VALUES (%s,%s,%s,%s,%s,%s)", ("bitswall", transId, reward, hash, user_ip, current_datetime))
				db.commit()
				return "ok"
			else:
				return "Error: Invalid transaction"
	else:
		return render_template('404.html')

@app.route('/about')
def about():
	clearsession()
	return render_template('about.html', title = 'About | Nimiq Faucet')

@app.route('/faq')
def faq():
	clearsession()
	return render_template('faq.html', title = 'FAQ | Nimiq Faucet')

@app.route('/adblock')
def adblock():
	clearsession()
	return render_template('adblock.html', title = 'Adblock Detected | Nimiq Faucet')

@app.route('/transaction')
def transaction():
	if "wallet_address" and "ip_address" and "hash" in session:
		cursor.execute("SELECT * FROM users WHERE wallet_address = %s AND ip_address = %s", (session["wallet_address"], session["ip_address"], ))
		user = cursor.fetchone()
		cooldown_time = datetime.datetime.strptime(user[2], "%Y-%m-%d %H:%M:%S")
		total_cooldown_time = cooldown_time + datetime.timedelta(minutes=15)
		
		current_time = datetime.datetime.utcnow().replace(microsecond=0)
		time_left_in_seconds = int((total_cooldown_time - current_time).total_seconds()) if int((total_cooldown_time - current_time).total_seconds()) > 0 else 0
		return render_template('transaction.html', session_wallet_address=session['wallet_address'], session_hash=session['hash'], session_value_nimtoshis=session['value_nimtoshis'], cooldown_time=time_left_in_seconds)

	elif "wallet_address" and "ip_address" in session:
		cursor.execute("SELECT * FROM users WHERE wallet_address = %s AND ip_address = %s", (session["wallet_address"], session["ip_address"], ))
		user = cursor.fetchone()
		cooldown_time = datetime.datetime.strptime(user[2], "%Y-%m-%d %H:%M:%S")
		total_cooldown_time = cooldown_time + datetime.timedelta(minutes=15)
		
		current_time = datetime.datetime.utcnow().replace(microsecond=0)
		time_left_in_seconds = int((total_cooldown_time - current_time).total_seconds()) if int((total_cooldown_time - current_time).total_seconds()) > 0 else 0
		return render_template('tnsfail.html', cooldown_time=time_left_in_seconds)

	elif "wallet_address" in session:
		cursor.execute("SELECT * FROM users WHERE wallet_address = %s", (session["wallet_address"], ))
		user = cursor.fetchone()
		cooldown_time = datetime.datetime.strptime(user[2], "%Y-%m-%d %H:%M:%S")
		total_cooldown_time = cooldown_time + datetime.timedelta(minutes=15)
		
		current_time = datetime.datetime.utcnow().replace(microsecond=0)
		time_left_in_seconds = int((total_cooldown_time - current_time).total_seconds()) if int((total_cooldown_time - current_time).total_seconds()) > 0 else 0
		return render_template('tnsfail.html', cooldown_time=time_left_in_seconds)

	elif "ip_address" in session:
		cursor.execute("SELECT * FROM users WHERE ip_address = %s", (session["ip_address"], ))
		user = cursor.fetchone()
		cooldown_time = datetime.datetime.strptime(user[2], "%Y-%m-%d %H:%M:%S")
		total_cooldown_time = cooldown_time + datetime.timedelta(minutes=15)
		
		current_time = datetime.datetime.utcnow().replace(microsecond=0)
		time_left_in_seconds = int((total_cooldown_time - current_time).total_seconds()) if int((total_cooldown_time - current_time).total_seconds()) > 0 else 0
		return render_template('tnsfail.html', cooldown_time=time_left_in_seconds)

	else:
		return render_template('404.html')

'''@app.route('/shortlinktns')
def shortlinktns():

	if "wallet_address" and "ip_address" and "hash" in session:
		if session["shortlink_name"] == "tnyso":
			cursor.execute("SELECT * FROM tnyso_shortlink WHERE ip_address = %s", (session["ip_address"], ))
			user = cursor.fetchone()
			cooldown_time = datetime.datetime.strptime(user[3], "%Y-%m-%d %H:%M:%S")
			total_cooldown_time = cooldown_time + datetime.timedelta(days=1)
			
			current_time = datetime.datetime.utcnow().replace(microsecond=0)
			time_left_in_seconds = int((total_cooldown_time - current_time).total_seconds()) if int((total_cooldown_time - current_time).total_seconds()) > 0 else 0
			return render_template('sl_transaction.html', session_wallet_address=session['wallet_address'], session_hash=session['hash'], session_value_nimtoshis=session['value_nimtoshis'], cooldown_time=time_left_in_seconds)
		else:
			return render_template('404.html')

	elif "ip_address" and "shortlink_name" in session:
		if session["shortlink_name"] == "tnyso":
			cursor.execute("SELECT * FROM tnyso_shortlink WHERE ip_address = %s", (session["ip_address"], ))
			user = cursor.fetchone()
			cooldown_time = datetime.datetime.strptime(user[3], "%Y-%m-%d %H:%M:%S")
			total_cooldown_time = cooldown_time + datetime.timedelta(days=1)
			
			current_time = datetime.datetime.utcnow().replace(microsecond=0)
			time_left_in_seconds = int((total_cooldown_time - current_time).total_seconds()) if int((total_cooldown_time - current_time).total_seconds()) > 0 else 0
			return render_template('sl_tnsfail.html', cooldown_time=time_left_in_seconds, frequency="once")
		else:
			return render_template('404.html')
	else:
		return render_template('404.html')'''

@app.route('/checkwalletaddress', methods=['POST', 'GET'])
def checkwalletaddress():
	if request.method == 'POST':
		if hcaptcha.verify():
			wallet_address = str(request.form.get('offerwall_wallet_address', None))

			url = f"https://api.nimiq.cafe/account/{wallet_address}?api_key={nimiq_api}"
			response = requests.get(url)
			if response.status_code == 200:
				session.permanent = True
				session["offerwall_wallet_address"] = wallet_address
				return redirect(url_for('offerwall'))
			else:
				flash("Invalid Nimiq address. Please try again!", "warning")
				return redirect(url_for('offerwall'))
		else:
			flash("Please verify that you are not a robot by solving the captcha challenge.", "warning")
			return redirect(url_for('offerwall'))

@app.route('/status', methods=['POST', 'GET'])
def status():
	if request.method == 'POST':
		if hcaptcha.verify():
			clearsession()
			wallet_address = str(request.form.get('wallet_address', None))
			ip_address = str(request.environ.get('HTTP_X_FORWARDED_FOR')).split(', ')[0]

			url = f"https://api.nimiq.cafe/account/{wallet_address}?api_key={nimiq_api}"
			response = requests.get(url)
			
			if response.status_code == 200:
				cursor.execute("SELECT * FROM users WHERE wallet_address=%s", (wallet_address, ))
				check_wallet_address = cursor.fetchone()
				if check_wallet_address is None:
					cursor.execute("SELECT * FROM users WHERE ip_address=%s", (ip_address, ))
					check_ip_address = cursor.fetchone()

					if check_ip_address is None:
						session["wallet_address"] = wallet_address
						session["ip_address"] = ip_address
						session["hash"] = sendNimiq(wallet_address)

						current_datetime = str(datetime.datetime.utcnow().replace(microsecond=0))
						cursor.execute("INSERT INTO users (wallet_address, ip_address, datetime) VALUES (%s,%s,%s)", (wallet_address, ip_address, current_datetime))
						#cursor.execute("INSERT INTO transactions (hash, wallet_address, ip_address, datetime) VALUES (%s,%s,%s,%s)", (session["hash"], wallet_address, ip_address, current_datetime))
						db.commit()
						return redirect(url_for('transaction'))
						#save transaction info and add user data

					else:
						cooldown_time = datetime.datetime.strptime(check_ip_address[2], "%Y-%m-%d %H:%M:%S")
						total_cooldown_time = cooldown_time + datetime.timedelta(minutes=15)
						
						current_time = datetime.datetime.utcnow().replace(microsecond=0)
						ip_address_time_left_in_seconds = int((total_cooldown_time - current_time).total_seconds())

						if ip_address_time_left_in_seconds < 0:
							session["wallet_address"] = wallet_address
							session["ip_address"] = ip_address
							session["hash"] = sendNimiq(wallet_address)

							current_datetime = str(datetime.datetime.utcnow().replace(microsecond=0))
							cursor.execute("UPDATE users SET wallet_address = %s, datetime = %s WHERE ip_address = %s", (wallet_address, current_datetime, ip_address))
							#cursor.execute("INSERT INTO transactions (hash, wallet_address, ip_address, datetime) VALUES (?,?,?,?)", (session["hash"], wallet_address, ip_address, current_datetime))
							db.commit()
							return redirect(url_for('transaction'))
							#save transaction info and update user data for different address and same ip
						else:
							session["ip_address"] = ip_address
							return redirect(url_for('transaction'))
							#deny payment

				else:
					cooldown_time = datetime.datetime.strptime(check_wallet_address[2], "%Y-%m-%d %H:%M:%S")
					total_cooldown_time = cooldown_time + datetime.timedelta(minutes=15)
					
					current_time = datetime.datetime.utcnow().replace(microsecond=0)
					wallet_address_time_left_in_seconds = int((total_cooldown_time - current_time).total_seconds())

					if wallet_address_time_left_in_seconds < 0:
						cursor.execute("SELECT * FROM users WHERE ip_address = %s", (ip_address, ))
						check_ip_address = cursor.fetchone()

						if check_ip_address is None:
							session["wallet_address"] = wallet_address
							session["ip_address"] = ip_address
							session["hash"] = sendNimiq(wallet_address)

							current_datetime = str(datetime.datetime.utcnow().replace(microsecond=0))
							cursor.execute("UPDATE users SET ip_address = %s, datetime = %s WHERE wallet_address = %s", (ip_address, current_datetime, wallet_address))
							#cursor.execute("INSERT INTO transactions (hash, wallet_address, ip_address, datetime) VALUES (?,?,?,?)", (session["hash"], wallet_address, ip_address, current_datetime))
							db.commit()
							return redirect(url_for('transaction'))
							#save transaction info and update user data for same address and different ip
						
						else:
							cooldown_time = datetime.datetime.strptime(check_ip_address[2], "%Y-%m-%d %H:%M:%S")
							total_cooldown_time = cooldown_time + datetime.timedelta(minutes=15)
							
							current_time = datetime.datetime.utcnow().replace(microsecond=0)
							ip_address_time_left_in_seconds = int((total_cooldown_time - current_time).total_seconds())

							if ip_address_time_left_in_seconds < 0:
								session["wallet_address"] = wallet_address
								session["ip_address"] = ip_address
								session["hash"] = sendNimiq(wallet_address)

								current_datetime = str(datetime.datetime.utcnow().replace(microsecond=0))
								cursor.execute("UPDATE users SET datetime = %s WHERE wallet_address = %s AND ip_address = %s", (current_datetime, wallet_address, ip_address))
								#cursor.execute("INSERT INTO transactions (hash, wallet_address, ip_address, datetime) VALUES (?,?,?,?)", (session["hash"], wallet_address, ip_address, current_datetime))
								db.commit()
								return redirect(url_for('transaction'))
								#save transaction info and update user data for both same address and same ip
							else:
								session["wallet_address"] = wallet_address
								session["ip_address"] = ip_address
								return redirect(url_for('transaction'))
					else:
						session["wallet_address"] = wallet_address
						return redirect(url_for('transaction'))

			else:
				flash("Invalid Nimiq address. Please try again!", "warning")
				return redirect(url_for('index'))
		else:
			flash("Please verify that you are not a robot by solving the captcha challenge.", "warning")
			return redirect(url_for('index'))
	else:
		return render_template('404.html')


'''@app.route('/shortlink-status', methods=['POST', 'GET'])
def shortlink_status():
	if request.method == 'POST':
		if hcaptcha.verify():
			clearsession()
			wallet_address = str(request.form.get('wallet_address', None))
			ip_address = str(request.environ.get('HTTP_X_FORWARDED_FOR')).split(', ')[0]
			
			url = f'http://ip-api.com/json/{ip_address}?fields=status,message,proxy,hosting,query'
			response = requests.get(url).json()
			if response["status"] == "success":
				if response["proxy"] is False and response["hosting"] is False:
					url = f"https://api.nimiq.cafe/account/{wallet_address}?api_key={nimiq_api}"
					response = requests.get(url)
					
					if response.status_code == 200:
						if "tnyso" in request.form:
							cursor.execute("SELECT * FROM tnyso_shortlink WHERE ip_address=%s", (ip_address, ))
							check_ip_address = cursor.fetchone()

							if check_ip_address is None:
								cursor.execute("SELECT reward_id FROM tnyso_shortlink")
								check_reward_id = cursor.fetchall()
								if not check_reward_id:
									reward_id = ''.join(secrets.choice(string.ascii_letters + string.digits) for x in range(10))
								else:
									while True:
										reward_id = ''.join(secrets.choice(string.ascii_letters + string.digits) for x in range(10))
										if reward_id in check_reward_id[0]:
											continue
										else:
											break

								destination_url = f"https://nimiqfaucet.xyz/tnyso/{reward_id}"
								url = f"https://tny.so/api?api={tnyso_api_key}&url={destination_url}"
								response = requests.get(url).json()
								link = response["shortenedUrl"]

								cursor.execute("INSERT INTO tnyso_shortlink (wallet_address, ip_address, datetime, reward_id, link, status) VALUES (%s,%s,%s,%s,%s,%s)", (wallet_address, ip_address, "None", reward_id, link, "pending"))
								db.commit()
								return redirect(link)

							else:
								if check_ip_address[6] == "pending":
									link = check_ip_address[5]
									return redirect(link)

								elif check_ip_address[6] == "completed":
									cooldown_time = datetime.datetime.strptime(check_ip_address[3], "%Y-%m-%d %H:%M:%S")
									total_cooldown_time = cooldown_time + datetime.timedelta(days=1)
									
									current_time = datetime.datetime.utcnow().replace(microsecond=0)
									ip_address_time_left_in_seconds = int((total_cooldown_time - current_time).total_seconds())

									if ip_address_time_left_in_seconds < 0:
										cursor.execute("SELECT reward_id FROM tnyso_shortlink")
										check_reward_id = cursor.fetchall()
										if not check_reward_id:
											reward_id = ''.join(secrets.choice(string.ascii_letters + string.digits) for x in range(10))
										else:
											while True:
												reward_id = ''.join(secrets.choice(string.ascii_letters + string.digits) for x in range(10))
												if reward_id in check_reward_id[0]:
													continue
												else:
													break

										destination_url = f"https://nimiqfaucet.xyz/tnyso/{reward_id}"
										url = f"https://tny.so/api?api={tnyso_api_key}&url={destination_url}"
										response = requests.get(url).json()
										link = response["shortenedUrl"]
										cursor.execute("UPDATE tnyso_shortlink SET datetime = %s, reward_id = %s, link = %s, status = %s WHERE ip_address = %s", ("None", reward_id, link, "pending", ip_address))
										db.commit()
										return redirect(link)
									else:
										session["ip_address"] = ip_address
										session["shortlink_name"] = "tnyso"
										return redirect(url_for('shortlinktns'))
						else:
							flash("Something went wrong. Pleae try again!", "warning")
							return redirect(url_for('shortlink'))
					else:
						flash("Invalid Nimiq address. Please try again!", "warning")
						return redirect(url_for('shortlink'))
				else:
					flash("VPNs & Proxies are not allowed for shortlinks!", "warning")
					return redirect(url_for('shortlink'))
			else:
				flash("Could not verify IP address information. Please try again in a minute!", "warning")
				return redirect(url_for('shortlink'))
		else:
			flash("Please verify that you are not a robot by solving the captcha challenge.", "warning")
			return redirect(url_for('shortlink'))
	else:
		return render_template('404.html')'''

'''@app.route('/tnyso/<id>', methods=['GET'])
def tnyso(id):
	cursor.execute("SELECT reward_id FROM tnyso_shortlink")
	check_reward_id = cursor.fetchall()

	if id in check_reward_id[0]:
		cursor.execute("SELECT * FROM tnyso_shortlink WHERE reward_id=%s", (id, ))
		user = cursor.fetchone()
		session["wallet_address"] = user[1]
		session["ip_address"] = user[2]
		session["hash"] = sendNimiq(user[1], 25000, 37500)
		session["shortlink_name"] = "tnyso"

		current_datetime = str(datetime.datetime.utcnow().replace(microsecond=0))
		cursor.execute("UPDATE tnyso_shortlink SET datetime = %s, status = %s WHERE ip_address = %s", (current_datetime, "completed", session["ip_address"]))
		db.commit()
		return redirect(url_for("shortlinktns"))
	else:
		return render_template('404.html')'''

@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
	try:
		pages = []
		ten_days_ago = (datetime.datetime.now() - datetime.timedelta(days=7)).date().isoformat()
		#static pages
		for rule in app.url_map.iter_rules():
			if "GET" in rule.methods and len(rule.arguments) == 0:
				pages.append(["http://nimiqfaucet.xyz" + str(rule.rule), ten_days_ago])

		sitemap_xml = render_template('sitemap_template.xml', pages=pages)
		response = make_response(sitemap_xml)
		response.headers['Content-Type'] = 'application/xml'

		return response
	except Exception as e:
		return(str(e))


if __name__ == '_main_':
	app._static_folder = 'static'
	app.run(debug=False)