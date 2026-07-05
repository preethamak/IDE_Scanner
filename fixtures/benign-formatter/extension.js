const vscode = require("vscode");

function activate(context) {
  const disposable = vscode.commands.registerCommand("trustedFormatter.format", () => {
    vscode.window.showInformationMessage("Formatted");
  });
  context.subscriptions.push(disposable);
}

module.exports = { activate };
