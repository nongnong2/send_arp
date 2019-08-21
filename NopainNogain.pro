TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        arp.cpp \
        main.cpp
LIBS+=-lpcap -lpthread

HEADERS += \
    send_arp.h
