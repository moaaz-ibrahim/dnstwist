#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r'''
Created by Marcin Ulikowski <marcin@ulikowski.pl>
Modified and added new features by Moaaz Ibrahim (github:moaaz-ibrahim)

Licensed under the Apache License, Version 2.0 (the "License");
'''

import os
import time
import threading
from queue import Queue
from uuid import uuid4
from flask import Flask, request, jsonify, send_from_directory
import dnstwist
import whois
import concurrent.futures
import functools
import redis
import json

PORT = int(os.environ.get('PORT', 8000))
HOST = os.environ.get('HOST', '127.0.0.1')
THREADS = int(os.environ.get('THREADS', dnstwist.THREAD_COUNT_DEFAULT))
NAMESERVERS = os.environ.get('NAMESERVERS') or os.environ.get('NAMESERVER')
SESSION_TTL = int(os.environ.get('SESSION_TTL', 3600))
SESSION_MAX = int(os.environ.get('SESSION_MAX', 10))
DOMAIN_MAXLEN = int(os.environ.get('DOMAIN_MAXLEN', 15))
WEBAPP_HTML = os.environ.get('WEBAPP_HTML', 'webapp.html')
WEBAPP_DIR = os.environ.get('WEBAPP_DIR', os.path.dirname(os.path.abspath(__file__)))
REDIS_PREFIX = os.environ.get('REDIS_PREFIX', 'dnstwist:')
QUEUE_KEY = os.environ.get('QUEUE_KEY', 'typosquatting:scan_queue')
SCAN_LIMIT = int(os.environ.get('SCAN_LIMIT', 100))

print("Testing Redis connection...")
print(f"REDIS_HOST: {os.environ.get('REDIS_HOST', 'localhost')}")
print(f"REDIS_PORT: {os.environ.get('REDIS_PORT', 6379)}")
print(f"REDIS_PASSWORD: {'*' * len(os.environ.get('REDIS_PASSWORD', ''))}") # Hide password in logs

try:
    client = redis.Redis(
        host=os.environ.get('REDIS_HOST', 'localhost'),
        port=int(os.environ.get('REDIS_PORT', 6379)),
        db=int(os.environ.get('REDIS_DB', 0)),
        password=os.environ.get('REDIS_PASSWORD'),  # Add password authentication
        decode_responses=True
    )
    
    result = client.ping()
    print(f"✅ Redis PING successful: {result}")
    
    # Test basic operations
    client.set("test_key", "hello_world")
    value = client.get("test_key")
    print(f"✅ Redis SET/GET successful: {value}")
    
except redis.ConnectionError as e:
    print(f"❌ Redis ConnectionError: {e}")
except redis.AuthenticationError as e:
    print(f"❌ Redis Authentication Error: {e}")
except Exception as e:
    print(f"❌ Other error: {e}")

DOMAIN_BLOCKLIST = []

DICTIONARY = (
    'auth', 'account', 'confirm', 'connect', 'enroll', 'http', 'https', 'info', 'login', 'mail', 'my',
    'online', 'payment', 'portal', 'recovery', 'register', 'ssl', 'safe', 'secure', 'signin', 'signup', 'support',
    'update', 'user', 'verify', 'verification', 'web', 'www'
)
TLD_DICTIONARY = (
    'com', 'net', 'org', 'info', 'cn', 'co', 'eu', 'de', 'uk', 'pw', 'ga', 'gq', 'tk', 'ml', 'cf',
    'app', 'biz', 'top', 'xyz', 'online', 'site', 'live'
)

sessions = []
app = Flask(__name__)

def janitor(sessions):
    while True:
        time.sleep(1)
        for s in sorted(sessions, key=lambda x: x.timestamp):
            if s.jobs.empty() and s.threads:
                s.stop()
                continue
            if (s.timestamp + SESSION_TTL) < time.time():
                sessions.remove(s)
                continue

def get_whois_creation_date(domain):
    try:
        print(f"[WHOIS] Looking up {domain}")
        data = whois.whois(domain)
        creation_date = data.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return str(creation_date) if creation_date else None
    except Exception as e:
        print(f"[WHOIS] Lookup failed for {domain}: {str(e)}")
        return None

class Session:
    def __init__(self, url, nameservers=None, thread_count=THREADS):
        self.id = str(uuid4())
        self.timestamp = int(time.time())
        self.url = dnstwist.UrlParser(url)
        self.nameservers = nameservers
        self.thread_count = thread_count
        self.jobs = Queue()
        self.threads = []
        self.domains_results = []  # <-- Store enriched registered domains
        self.fuzzer = dnstwist.Fuzzer(self.url.domain, dictionary=DICTIONARY, tld_dictionary=TLD_DICTIONARY)
        self.fuzzer.generate()
        self.permutations = self.fuzzer.permutations
        self.registration_date_cache = {}
        self.registration_date_retry_count = {}
        self.whois_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        self.max_whois_retries = 3
        self.whois_retry_delay = 5
        self.scan_limit = SCAN_LIMIT

    def _async_whois(self, domain, retry_count=0, callback=None):
        if domain not in self.registration_date_cache or (
            self.registration_date_cache[domain] is None and retry_count < self.max_whois_retries
        ):
            def fetch_and_store():
                date = get_whois_creation_date(domain)
                self.registration_date_cache[domain] = date
                if date is not None and callback:
                    callback(date)
                elif retry_count < self.max_whois_retries:
                    self.registration_date_retry_count[domain] = retry_count + 1
                    threading.Timer(
                        self.whois_retry_delay,
                        lambda: self._async_whois(domain, retry_count + 1, callback)
                    ).start()
                else:
                    if callback:
                        callback(None)

            self.whois_executor.submit(fetch_and_store)

    def scan(self):
        for domain in self.fuzzer.domains:
            self.jobs.put(domain)
        for _ in range(self.thread_count):
            worker = dnstwist.Scanner(self.jobs)
            worker.option_extdns = dnstwist.MODULE_DNSPYTHON
            worker.option_geoip = dnstwist.MODULE_GEOIP
            if self.nameservers:
                worker.nameservers = self.nameservers.split(',')
            worker.start()
            self.threads.append(worker)

        tag_thread = threading.Thread(target=self.tag_registered_domains)
        tag_thread.daemon = True
        tag_thread.start()

    def stop(self):
        self.jobs.queue.clear()
        for worker in self.threads:
            worker.stop()
        for worker in self.threads:
            worker.join()
        self.threads.clear()

    def domains(self):
        return self.permutations(registered=True, unicode=True)

    def domains_paginated(self, limit=50, offset=0, include_registration_date=False):
        all_domains = self.permutations(registered=True, unicode=True)
        total_count = len(all_domains)
        start_idx = offset
        end_idx = offset + limit
        paginated_domains = all_domains[start_idx:end_idx]
        if include_registration_date:
            for domain_info in paginated_domains:
                if 'domain' in domain_info:
                    domain_name = domain_info['domain']
                    domain_info['registration_date'] = self.registration_date_cache.get(domain_name)
                    if domain_info['registration_date'] is None:
                        current_retries = self.registration_date_retry_count.get(domain_name, 0)
                        if current_retries < self.max_whois_retries:
                            self._async_whois(domain_name, retry_count=current_retries)
        return {
            'domains': paginated_domains,
            'pagination': {
                'total': total_count,
                'limit': limit,
                'offset': offset,
                'has_more': end_idx < total_count,
                'next_offset': end_idx if end_idx < total_count else None
            }
        }

    def tag_registered_domains(self):
        saved_results = set()  # Track domains that have been saved to results
        print("Starting tag_registered_domains")
        while any(t.is_alive() for t in self.threads):
            remaining = max(self.jobs.qsize(), len(self.threads))
            current_results_len = len(self.domains_results)
            print(f"Scanning Limit: {self.scan_limit}, Remaining: {remaining}, Current Results Length: {current_results_len}")
            if current_results_len >= self.scan_limit or remaining == 0:
                self.stop()
                print(f"Scanning Limit Reached: {self.scan_limit}, or Remaining: {remaining} is 0, Current Results Length: {current_results_len}")
                break
            
            for d in self.permutations(registered=True, unicode=True):
                if 'domain' in d:
                    print(f"Processing domain: {max(self.jobs.qsize(), len(self.threads))}")
                    domain_name = d['domain']
                    if domain_name not in saved_results:
                        print(f"Processing domain: {domain_name}")

                        domain_data = d.copy()

                        def save_result(date, domain_data=domain_data, domain_name=domain_name):
                            print(f"WHOIS callback received for {domain_name} with date: {date}")
                            if domain_name not in saved_results:
                                domain_data['creation_date'] = date
                                print(f"Adding domain to results: {domain_name} with data: {domain_data}")
                                self.domains_results.append(domain_data)
                                saved_results.add(domain_name)
                            else:
                                print(f"Skipping save for {domain_name} - already in results")

                        # Use functools.partial to bind the right values
                        self._async_whois(domain_name, callback=functools.partial(save_result))
                    else:
                        print(f"Skipping already saved domain: {domain_name}")
            print(f"Current results count: {len(self.domains_results)}")
            print(f"Saved results set: {saved_results}")
            time.sleep(2)  # Run every 2 seconds
        self.on_tagging_complete()

    def on_tagging_complete(self):
        print(f"Tagging complete, {self.url.domain} - {self.domains_results}")
        try:
            # Test Redis connection before proceeding
            if not client.ping():
                raise ConnectionError("Redis server is not responding")

            # Create a key for storing the scan results
            scan_key = f"{QUEUE_KEY}-scan:{self.url.domain}"
            
            # Prepare the data to store
            scan_data = {
                'scan_id': self.id,
                'domain': self.url.domain,
                'timestamp': self.timestamp,
                'results': self.domains_results,
                'total_domains': len(self.domains_results)
            }
            queue_key = f"{QUEUE_KEY}"
            # Store the scan results in Redis with expiration
            # client.setex(
            #     scan_key,
            #     SESSION_TTL,  # Use the same TTL as session (an hour)
            #     json.dumps(scan_data)
            # )
            
            # Add scan ID to a list of completed scans
            client.rpush(queue_key, json.dumps(scan_data))
            
            print(f"✅ Enqueued scan result for domain: {self.url.domain} in Redis list: {queue_key}")
        except ConnectionError as e:
            print(f"Redis connection error: {str(e)}")
            print(f"Please ensure Redis is running and accessible")
        except Exception as e:
            print(f"Error storing results in Redis: {str(e)}")

    def status(self):
        total = len(self.permutations())
        remaining = max(self.jobs.qsize(), len(self.threads))
        complete = total - remaining
        registered = len(self.permutations(registered=True))
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'url': self.url.full_uri(),
            'domain': self.url.domain,
            'total': total,
            'complete': complete,
            'remaining': remaining,
            'registered': registered
        }

    def csv(self):
        return dnstwist.Format(self.permutations(registered=True)).csv()

    def json(self):
        return dnstwist.Format(self.permutations(registered=True)).json()

    def list(self):
        return dnstwist.Format(self.permutations()).list()

@app.route('/')
def root():
    return send_from_directory(WEBAPP_DIR, WEBAPP_HTML)

@app.route('/api/scans', methods=['POST'])
def api_scan():
    if sum([1 for s in sessions if not s.jobs.empty()]) >= SESSION_MAX:
        return jsonify({'message': 'Too many scan sessions - please retry in a minute'}), 500
    j = request.get_json(force=True)
    if 'url' not in j:
        return jsonify({'message': 'Bad request'}), 400
    try:
        _, domain, _ = dnstwist.domain_tld(j.get('url'))
    except Exception:
        return jsonify({'message': 'Bad request'}), 400
    if len(domain) > DOMAIN_MAXLEN:
        return jsonify({'message': 'Domain name is too long'}), 400
    for block in DOMAIN_BLOCKLIST:
        if str(block) in domain:
            return jsonify({'message': 'Not allowed'}), 400
    try:
        session = Session(j.get('url'), nameservers=NAMESERVERS)
    except Exception:
        return jsonify({'message': 'Invalid domain name'}), 400
    else:
        session.scan()
        sessions.append(session)
    return jsonify(session.status()), 201

@app.route('/api/scans/<sid>')
def api_status(sid):
    for s in sessions:
        if s.id == sid:
            return jsonify(s.status())
    return jsonify({'message': 'Scan session not found'}), 404

@app.route('/api/scans/<sid>/domains')
def api_domains(sid):
    limit = request.args.get('limit', default=5, type=int)
    offset = request.args.get('offset', default=0, type=int)
    include_registration_date = request.args.get('include_registration_date', default='false').lower() == 'true'
    if limit <= 0 or limit > 1000:
        return jsonify({'message': 'Limit must be between 1 and 1000'}), 400
    if offset < 0:
        return jsonify({'message': 'Offset must be non-negative'}), 400
    for s in sessions:
        if s.id == sid:
            try:
                result = s.domains_paginated(limit=limit, offset=offset, include_registration_date=include_registration_date)
                return jsonify(result)
            except Exception as e:
                return jsonify({'message': f'Error retrieving domains: {str(e)}'}), 500
    return jsonify({'message': 'Scan session not found'}), 404

@app.route('/api/scans/<sid>/results')
def api_results(sid):
    for s in sessions:
        if s.id == sid:
            return jsonify(s.domains_results)
    return jsonify({'message': 'Scan session not found'}), 404

@app.route('/api/scans/<sid>/csv')
def api_csv(sid):
    for s in sessions:
        if s.id == sid:
            return s.csv(), 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=dnstwist.csv'}
    return jsonify({'message': 'Scan session not found'}), 404

@app.route('/api/scans/<sid>/json')
def api_json(sid):
    for s in sessions:
        if s.id == sid:
            return s.json(), 200, {'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename=dnstwist.json'}
    return jsonify({'message': 'Scan session not found'}), 404

@app.route('/api/scans/<sid>/list')
def api_list(sid):
    for s in sessions:
        if s.id == sid:
            return s.list(), 200, {'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename=dnstwist.txt'}
    return jsonify({'message': 'Scan session not found'}), 404

@app.route('/api/scans/<sid>/stop', methods=['POST'])
def api_stop(sid):
    for s in sessions:
        if s.id == sid:
            s.stop()
            sessions.remove(s)
            return jsonify({})
    return jsonify({'message': 'Scan session not found'}), 404

@app.route('/api/whois', methods=['GET'])
def get_domain_info():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Missing 'domain' query parameter"}), 400
    try:
        data = whois.whois(domain)
        creation_date = data.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return jsonify({
            "domain": domain,
            "creation_date": str(creation_date)
        })
    except Exception as e:
        return jsonify({
            "domain": domain,
            "error": f"WHOIS lookup failed: {str(e)}"
        }), 500

@app.route('/api/scans/in-process')
def api_in_process_scans():
    in_process = []
    for s in sessions:
        total = len(s.permutations())
        remaining = max(s.jobs.qsize(), len(s.threads))
        if remaining > 0:
            in_process.append({
                'id': s.id,
                'domain': s.url.domain,
                'total': total,
                'remaining': remaining,
                'complete': total - remaining,
                'registered': len(s.permutations(registered=True)),
                'timestamp': s.timestamp
            })
    return jsonify(in_process)

cleaner = threading.Thread(target=janitor, args=(sessions,))
cleaner.daemon = True
cleaner.start()

if __name__ == '__main__':
    app.run(host=HOST, port=PORT)