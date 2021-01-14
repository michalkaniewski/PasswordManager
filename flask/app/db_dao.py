import time
import flask
import pymysql
from .db import mysql
from bcrypt import hashpw, gensalt, checkpw
import datetime
from .AESCipher import AESCipher
import random


class DbDAO:
    def register_new_user(self, username, password, email):
        salt = gensalt(5)
        password = password.encode()
        hashed = hashpw(password, salt)
        sql = "INSERT INTO user(username, email, passhash) VALUES(%s, %s, %s)"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, (username, email, hashed))
        conn.commit()
        cursor.close() 
        conn.close()
    def is_username_unique(self, username):
        sql = "SELECT 1 FROM user WHERE username=%s"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, username)
        exists = cursor.fetchone()
        cursor.close() 
        conn.close()
        if exists and exists[0] == 1:
            return False
        else:
            return True
    def validate_password(self, username, password):
        sql = "SELECT passhash from user where username=%s"
        delay_time = random.uniform(0.3, 0.8)
        delay_sql = "DO SLEEP(%s)"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(delay_sql, delay_time)
        cursor.execute(sql, username)
        passhash = cursor.fetchone()
        cursor.close()
        conn.close()
        if passhash and checkpw(password.encode(), passhash[0]):
            conn = mysql.connect()
            cursor = conn.cursor()
            sql = "UPDATE user SET failedauth = 0, unlocktime = NULL WHERE username=%s"
            cursor.execute(sql, username)
            conn.commit()
            cursor.close()
            conn.close()
            return True
        else:
            if passhash:
                conn = mysql.connect()
                cursor = conn.cursor()
                sql = "UPDATE user SET failedauth = failedauth + 1 WHERE username=%s"
                cursor.execute(sql, username)
                conn.commit()
                cursor.close()
                conn.close()
                self.lock_account(username)
            return False
    def lock_account(self, username):
        conn = mysql.connect()
        cursor = conn.cursor()
        sql = "SELECT failedauth FROM user WHERE username=%s"
        cursor.execute(sql, username)
        failed_auth = cursor.fetchone()[0]
        if failed_auth >= 3:
            sql = "UPDATE user SET failedauth = 0, unlocktime = TIMESTAMPADD(MINUTE, 1, CURRENT_TIMESTAMP) WHERE username=%s"
            cursor.execute(sql, username)
            conn.commit()
            cursor.close()
            conn.close()
    def set_session(self, sid, username):
        stmt = "SELECT id FROM user WHERE username=%s"
        sql = "INSERT INTO session (sid, userid) VALUES (%s, %s)"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(stmt, username)
        userid = cursor.fetchone()[0]
        cursor.execute(sql, (sid, userid))
        conn.commit()
        cursor.close() 
        conn.close()
    def delete_session(self, sid):
        sql = "DELETE FROM session WHERE sid=%s"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, sid)
        conn.commit()
        cursor.close()
        conn.close()
    def delete_old_sessions(self):
        curr_time = int(time.time())
        sql="DELETE FROM session WHERE %s - UNIX_TIMESTAMP(created) > 1800 OR %s - UNIX_TIMESTAMP(refreshed) > 300"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, (curr_time, curr_time))
        conn.commit()
        cursor.close()
        conn.close()
    def refresh_session(self, sid):
        sql = "UPDATE session SET refreshed=CURRENT_TIMESTAMP WHERE sid=%s"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, sid)
        conn.commit()
        cursor.close()
    def get_username(self, sid):
        if not sid:
            return ""
        sql = "SELECT u.username FROM session s JOIN user u ON s.userid=u.id WHERE sid=%s"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, sid)
        username = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        if username:
            return username[0]
        return ""
    def get_user(self, sid):
        if not sid:
            return ""
        sql = "SELECT userid FROM session WHERE sid=%s"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, sid)
        uid = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        if uid:
            return uid[0]
        return ""
    def add_password(self, sid, service, password, key):
        aes = AESCipher(key)
        encrypted = aes.encrypt(password)
        uid = self.get_user(sid)
        sql = "INSERT INTO password (passcrypto, userid, service) VALUES (%s, %s, %s)"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, (encrypted, uid, service))
        conn.commit()
        cursor.close()
        conn.close()
    def get_users_passwords(self, sid):
        uid = self.get_user(sid)
        sql = "SELECT id, service FROM password WHERE userid=%s"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, uid)
        sql_res = cursor.fetchall()
        conn.commit()
        cursor.close()
        conn.close()
        passwords = []
        for obj in sql_res:
            password = {}
            password['id'] = obj[0]
            password['service'] = obj[1]
            passwords.append(password)
        return passwords
    def get_password(self, id, key, uid):
        sql = "SELECT passcrypto FROM password WHERE id=%s AND userid=%s"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, (id, uid))
        passcrypto = cursor.fetchone()[0]
        aes = AESCipher(key)
        try:
            decrypted = aes.decrypt(passcrypto)
        except:
            return ""
        return decrypted
    def is_account_locked(self, username):
        sql = "SELECT UNIX_TIMESTAMP(unlocktime) FROM user WHERE username=%s"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, username)
        unlocktime = cursor.fetchone()[0]
        if unlocktime and unlocktime > int(time.time()):
            return True
        return False
    def is_user_logged_in(self, username):
        sql = "SELECT 1 FROM session s JOIN user u ON s.userid=u.id WHERE username=%s"
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(sql, username)
        exists = cursor.fetchone()
        cursor.close() 
        conn.close()
        if exists and exists[0] == 1:
            return True
        else:
            return False 