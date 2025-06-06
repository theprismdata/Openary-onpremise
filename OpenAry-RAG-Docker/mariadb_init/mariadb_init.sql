USE llm_dev;
CREATE TABLE `tb_user` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `password` varchar(256) DEFAULT NULL COMMENT '비밀번호',
  `email` varchar(128) DEFAULT NULL COMMENT '이메일',
  `state` varchar(10) DEFAULT 'ACTIVE' COMMENT ' 상태 ACTIVE/INACTIVE',
  `wdate` datetime DEFAULT current_timestamp() COMMENT '생성일시',
  `udate` datetime DEFAULT current_timestamp() COMMENT '업데이트일시',
  `role` varchar(128) DEFAULT 'USER' COMMENT '사용자구분(USER/ADMIN/OPERATOR)',
  `lang` varchar(10) DEFAULT 'en' COMMENT '적용언어',
  `user_code` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=94 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `tb_llm_doc` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'id',
  `filename` varchar(256) DEFAULT NULL COMMENT '파일경로',
  `summary` longtext DEFAULT NULL COMMENT '요약',
  `filesize` int(11) DEFAULT NULL COMMENT '파일크기',
  `status` varchar(50) DEFAULT NULL COMMENT '상태(upload/processing/complete/delete)',
  `uploaded` datetime DEFAULT NULL COMMENT '등록일시',
  `process_start` datetime DEFAULT NULL COMMENT '처리시작일시',
  `process_end` datetime DEFAULT NULL COMMENT '처리종료일시',
  `etc` varchar(256) DEFAULT NULL COMMENT '기타정보',
  `userid` varchar(256) DEFAULT NULL COMMENT 'userid',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6477 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='문서관리';