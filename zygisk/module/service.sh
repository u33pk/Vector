# Extract the directory path and change directory
MODDIR="${0%/*}"
cd "$MODDIR" || exit 1

# gook 轨道:daemon 启动前等注入完成标记。vectord 开机会对 zygote 做
# ctl.restart(应用模块配置/校验注入态),而 gook 模式下 zygote 注入由
# gook_orchestrator(post-fs-data 阶段)完成 —— 两者赛跑会互相拆台:
# 要么 daemon 把已注入的 zygote 杀掉,要么编排器注到被换掉的旧 zygote。
# 等 /data/adb/.gook_lsp_injected(≤120s)再启动 daemon,注入先落位。
if [ -f /data/adb/.gook_lsp ]; then
  i=0
  while [ ! -f /data/adb/.gook_lsp_injected ] && [ $i -lt 240 ]; do
    i=$((i + 1))
    sleep 0.5
  done
  log -p i -t "vector-sh" "gook mode: waited $i polls for injection marker"
fi

# Start the daemon directly in the background within a private mount namespace
# gook 轨道加重试:注入编排器与新 zygote 的 system_server fork 是毫秒级竞速,
# 前 3 次可能全输(热启动 preload 仅 5-8s),放宽到 30 让 watcher 补注入收敛。
if [ -f /data/adb/.gook_lsp ]; then
  # P11 W3.3:5→10。冷开机实测 popsicle:bell-run 早期 dlopen 重试可拖到
  # EXEC+~10s,5 次供轮(≈8s)在注入完成前 1s 耗尽(round-5 实录)。
  unshare --propagation slave -m "$MODDIR/daemon" --system-server-max-retry=10 "$@" &
else
  unshare --propagation slave -m "$MODDIR/daemon" --system-server-max-retry=3 "$@" &
fi
