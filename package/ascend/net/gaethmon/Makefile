include $(TOPDIR)/rules.mk

PKG_NAME:=gaethmon
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/gaethmon
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+luci
	TITLE:=gaethmon -- send virtual personal info
endef

define Package/gaethmon/description
	Get the vritual personal info message to send.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -r ./src/* $(PKG_BUILD_DIR)/
endef

define Package/gaethmon/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/gaethmon $(1)/bin
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/gaethmon.init $(1)/etc/init.d/gaethmon
endef

$(eval $(call BuildPackage,gaethmon))