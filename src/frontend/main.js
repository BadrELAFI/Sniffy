const { app, BrowserWindow, Menu, ipcMain } = require('electron');
const path = require('path');
const sudo = require('sudo-prompt');
const { spawn } = require('child_process');

let mainWindow;
let pythonProcess;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1200,
    minHeight: 700,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true
    },
    icon: path.join(__dirname, 'assets/icon.png'),
    titleBarStyle: 'hiddenInset',
    show: false,
    backgroundColor: '#1a1a2e'
  });

  mainWindow.loadFile('index.html');

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    
    // DevTools 
      mainWindow.webContents.openDevTools();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  createMenu();
}

function createMenu() {
  const template = [
    {
      label: 'Sniffy',
      submenu: [
        {
          label: 'About Sniffy',
          role: 'about'
        },
        { type: 'separator' },
        {
          label: 'Quit',
          accelerator: 'CmdOrCtrl+Q',
          click: () => {
            app.quit();
          }
        }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'close' }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

// event handlers
app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// IPC handler
ipcMain.handle('get-app-version', () => {
  return app.getVersion();
});


ipcMain.handle('start-sniffer', async () => {
  return new Promise((resolve, reject) => {

    const script = path.join(__dirname, '..', 'backend', 'sniffer_bridge.py');

    pythonProcess = spawn('sudo', ['python3', script], {
      detached: true,
      stdio: 'pipe'
    });

    pythonProcess.stdout.on('data', (data) => {
      console.log(`PYTHON: ${data}`);
    });
    pythonProcess.stderr.on('data', (data) => {
      console.error(`PYTHON ERR: ${data}`);
    });
    pythonProcess.on('error', reject);
    pythonProcess.on('spawn', () => resolve('started'));
  });
});
