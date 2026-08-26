-- MySQL dump 10.13  Distrib 8.0.45, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: issuer
-- ------------------------------------------------------
-- Server version	8.0.45

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `dbissuedcredential`
--

DROP TABLE IF EXISTS `dbissuedcredential`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dbissuedcredential` (
  `id` int NOT NULL AUTO_INCREMENT,
  `register_id` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `credential_configuration_id` varchar(200) NOT NULL,
  `issued_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `revoked` tinyint(1) NOT NULL DEFAULT '0',
  `revoked_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_grant_config` (`register_id`,`credential_configuration_id`)
) ENGINE=InnoDB AUTO_INCREMENT=345 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dbissuerlog`
--

DROP TABLE IF EXISTS `dbissuerlog`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dbissuerlog` (
  `id` int NOT NULL AUTO_INCREMENT,
  `team_id` varchar(50) NOT NULL,
  `credential_type` varchar(100) DEFAULT NULL,
  `holder_did` varchar(255) DEFAULT NULL,
  `issuer_did` varchar(255) DEFAULT NULL,
  `offer_id` varchar(100) DEFAULT NULL,
  `status` enum('success','failed') NOT NULL,
  `error_code` varchar(100) DEFAULT NULL,
  `error_message` text,
  `credential_payload` longtext,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_team` (`team_id`),
  KEY `idx_status` (`status`),
  KEY `idx_created` (`created_at`)
) ENGINE=InnoDB AUTO_INCREMENT=1158 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dbnonce`
--

DROP TABLE IF EXISTS `dbnonce`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dbnonce` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nonce` varchar(100) NOT NULL,
  `expires_at` datetime NOT NULL,
  `used` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_nonce` (`nonce`)
) ENGINE=InnoDB AUTO_INCREMENT=480 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dbregister`
--

DROP TABLE IF EXISTS `dbregister`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dbregister` (
  `ID` char(36) COLLATE utf8mb4_general_ci NOT NULL,
  `RegisterName` varchar(150) COLLATE utf8mb4_general_ci NOT NULL,
  `ContactName` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `RegisterDate` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `IsIssuer` tinyint(1) NOT NULL DEFAULT '0',
  `IsHolder` tinyint(1) NOT NULL DEFAULT '0',
  `IsVerifier` tinyint(1) NOT NULL DEFAULT '0',
  `IsAdmin` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dbrequest`
--

DROP TABLE IF EXISTS `dbrequest`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dbrequest` (
  `ID` int NOT NULL AUTO_INCREMENT,
  `RegisterID` char(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `CredentialId` varchar(1000) COLLATE utf8mb4_general_ci NOT NULL,
  `CreateDate` datetime(6) DEFAULT NULL,
  `PreAuthorizedCode` longtext COLLATE utf8mb4_general_ci,
  `subject` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `title_th` varchar(50) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `first_name_th` varchar(100) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `last_name_th` varchar(100) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `birth_date` varchar(20) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `gender` varchar(10) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `address` varchar(500) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `date_of_issuance` varchar(20) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `date_of_expiry` varchar(20) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `title_en` varchar(50) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `first_name_en` varchar(100) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `last_name_en` varchar(100) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `tx_code_hash` varchar(64) COLLATE utf8mb4_general_ci DEFAULT NULL,
  PRIMARY KEY (`ID`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=1435 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dbusers`
--

DROP TABLE IF EXISTS `dbusers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dbusers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `first_name` varchar(100) DEFAULT NULL,
  `last_name` varchar(100) DEFAULT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping events for database 'issuer'
--

--
-- Dumping routines for database 'issuer'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-08-26  0:29:24
