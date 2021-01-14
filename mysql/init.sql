DROP DATABASE IF EXISTS safeapp;
CREATE DATABASE safeapp;
use safeapp;

CREATE TABLE `user` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `passhash` BINARY(60) NOT NULL,
  `failedauth` int unsigned DEFAULT 0,
  `unlocktime` DATETIME DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE `session` (
  `sid` varchar(32) NOT NULL,
  `userid` int unsigned NOT NULL,
  `created` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `refreshed` DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`sid`),
  FOREIGN KEY (userid) REFERENCES user(id)
);

CREATE TABLE `password` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `passcrypto` varchar(128) NOT NULL,
  `userid` int unsigned NOT NULL,
  `service` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (userid) REFERENCES user(id)
);
