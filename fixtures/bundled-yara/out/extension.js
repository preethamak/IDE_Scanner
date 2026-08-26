const vscode = require('vscode');

function activate(context) {
  const decorator = vscode.window.createTextEditorDecorationType({});
  if (vscode.window.activeTextEditor) {
    vscode.window.activeTextEditor.setDecorations(decorator, []);
  }
}

module.exports = { activate };
