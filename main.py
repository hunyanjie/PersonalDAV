import logging
from tkinterdnd2 import TkinterDnD
from ui.app import DAVServerApp

def main():
    """程序入口点"""
    # 基础控制台日志配置
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # 使用 TkinterDnD.Tk 以支持拖拽功能
    root = TkinterDnD.Tk()
    
    # 创建应用程序实例
    app = DAVServerApp(root)
    
    # 绑定窗口关闭事件
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # 进入主循环
    root.mainloop()

if __name__ == "__main__":
    main()
