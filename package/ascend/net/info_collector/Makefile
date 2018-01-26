include $(TOPDIR)/rules.mk

PKG_NAME:=info_collector
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/info_collector
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+luci
	TITLE:=info_collector -- send info
endef

define Package/info_collector/description
	Get the info message to send.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/info_collector/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sendinfo $(1)/bin
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/sendinfo.init $(1)/etc/init.d/sendinfo
endef

$(eval $(call BuildPackage,info_collector))