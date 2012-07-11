# New ports collection makefile for:	ezjail_restartd
# Date created:		10 jul 2012
# Whom:			
#
# $FreeBSD$
#

PORTNAME=	ezjail_restartd
PORTVERSION=	0.1
CATEGORIES=	sysutils
MASTER_SITES=	#none
DISTFILES=	#none

MAINTAINER=	not_maintained
COMMENT=	Ezjail restart triggerd from within the jail

USE_RC_SUBR=	ezjail_restartd

SRC=		${.CURDIR}/src

LDFLAGS+=	-lutil

CFLAGS+=	-W -Wall

do-fetch:
	@${DO_NADA}

do-configure:
	@${DO_NADA}

do-build:
	${CC} ${CFLAGS} ${LDFLAGS} -o ${WRKSUBDIR}/ezjail_restartd ${SRC}/ezjail_restartd.c

do-install:
	${INSTALL_PROGRAM} ${WRKSUBDIR}/ezjail_restartd	${PREFIX}/sbin/ezjail_restartd

.include <bsd.port.mk>
