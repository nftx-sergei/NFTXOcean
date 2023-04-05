package=prometheus_cpp
$(package)_version=1.1.0
$(package)_download_path=https://github.com/jupp0r/prometheus-cpp/releases/download/v$($(package)_version)
$(package)_file_name=prometheus-cpp-with-submodules.tar.gz
$(package)_sha256_hash=522b6a57f474c89098fcdf198bd63796c65ee2e07b85b1d118be8e8b47148188
$(package)_patches=

define $(package)_preprocess_cmds
endef

define $(package)_config_cmds
	$($(package)_cmake) . -DBUILD_SHARED_LIBS=OFF -DENABLE_PUSH=OFF -DENABLE_COMPRESSION=OFF
endef

define $(package)_build_cmds
	$(MAKE) core pull -j$(nproc)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
endef
