CREATE DATABASE IF NOT EXISTS `pythonlogin` DEFAULT CHARACTER SET utf8 COLLATE
utf8_general_ci;
USE `pythonlogin`;

CREATE TABLE IF NOT EXISTS `accounts` (
`id` int(11) NOT NULL AUTO_INCREMENT,
`username` varchar(50) NOT NULL,
`password` varchar(255) NOT NULL,
`email` varchar(100) NOT NULL,
`points` INT NOT NULL DEFAULT(0),
PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

 INSERT INTO `accounts` (`id`, `username`, `password`, `email`, `points`) VALUES (1, 'test', 'test', 'test@test.com', 100);

select*from accounts;
