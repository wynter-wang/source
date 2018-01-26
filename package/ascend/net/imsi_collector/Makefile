include $(TOPDIR)/rules.mk

PKG_NAME:=imsi_collector
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/imsi_collector
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+luci
	TITLE:=imsi_collector -- send imsi info
endef

define Package/imsi_collector/description
	Get the imsi info message to send.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/imsi_collector/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sendimsi $(1)/bin
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/sendimsi.init $(1)/etc/init.d/sendimsi
endef

$(eval $(call BuildPackage,imsi_collector))