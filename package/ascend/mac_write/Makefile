include $(TOPDIR)/rules.mk

PKG_NAME:=mac_write
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/mac_write
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=mac_write -- change interface mac address
endef

define Package/mac_write/description
	Change interface mac address automatically
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/mac_write/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mac_write $(1)/bin
endef

$(eval $(call BuildPackage,mac_write))