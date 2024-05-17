AM_CPPFLAGS = $(OPENSSL_INCLUDES) -I../.. -I$(srcdir)/../.. -Wall
AM_CXXFLAGS = -Wall -Wextra -Werror
EXTRA_DIST = .indent.pro 

noinst_LTLIBRARIES = libtskbitlocker.la
libtskbitlocker_la_SOURCES = BitlockerParser.cpp DataTypes.cpp BitlockerUtils.cpp MetadataValueUnicode.cpp MetadataEntry.cpp MetadataUtils.cpp MetadataValueAesCcmEncryptedKey.cpp MetadataValueKey.cpp MetadataValueOffsetAndSize.cpp MetadataValueStretchKey.cpp MetadataValueVolumeMasterKey.cpp

indent:
	indent *.c *.cpp *.h *.hpp

clean-local:
	-rm -f *.c~ *.cpp~ *.h~ *.hpp~