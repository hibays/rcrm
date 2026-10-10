#include "flutter_window.h"

#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>
#include <windows.h>

#include <optional>

#include "flutter/generated_plugin_registrant.h"

namespace {

// Moves the window the way a mouse drag on a real title bar would.
//
// The app draws its own title bar, so there is no caption to press and the drag
// has to be started from Dart. Doing it with window_manager's
// startDragging() -- WM_SYSCOMMAND + SC_MOVE -- works on Windows 11, which lets
// keyboard-initiated moves snap, but Windows 10's Aero Snap only engages for a
// move the *mouse* started, so on Windows 10 the window does not snap at all.
//
// Handing the system a mouse-initiated non-client press instead is what
// Electron, Tauri and winit all do for their custom title bars, and it snaps on
// both: release the capture (so the button is ours to hand over) and post
// WM_NCLBUTTONDOWN with HTCAPTION, which makes the default window procedure run
// its real caption drag. PostMessage, not SendMessage, so the platform thread
// keeps running Flutter while the modal move loop is up.
void StartMouseInitiatedDrag(HWND window) {
  if (window == nullptr) {
    return;
  }
  // Nothing to drag in a fullscreen/borderless window (window_manager strips the
  // resize frame and the app reports its own fullscreen state as well).
  if ((GetWindowLongPtr(window, GWL_STYLE) & WS_THICKFRAME) == 0) {
    return;
  }
  ReleaseCapture();
  PostMessage(window, WM_NCLBUTTONDOWN, HTCAPTION, 0);
}

}  // namespace

FlutterWindow::FlutterWindow(const flutter::DartProject& project)
    : project_(project) {}

FlutterWindow::~FlutterWindow() {}

bool FlutterWindow::OnCreate() {
  if (!Win32Window::OnCreate()) {
    return false;
  }

  RECT frame = GetClientArea();

  // The size here must match the window dimensions to avoid unnecessary surface
  // creation / destruction in the startup path.
  flutter_controller_ = std::make_unique<flutter::FlutterViewController>(
      frame.right - frame.left, frame.bottom - frame.top, project_);
  // Ensure that basic setup of the controller was successful.
  if (!flutter_controller_->engine() || !flutter_controller_->view()) {
    return false;
  }
  RegisterPlugins(flutter_controller_->engine());
  SetChildContent(flutter_controller_->view()->GetNativeWindow());

  window_channel_ =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          flutter_controller_->engine()->messenger(), "rcrm/window",
          &flutter::StandardMethodCodec::GetInstance());
  window_channel_->SetMethodCallHandler(
      [this](const flutter::MethodCall<flutter::EncodableValue>& call,
             std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>
                 result) {
        if (call.method_name() == "startWindowDrag") {
          StartMouseInitiatedDrag(GetHandle());
          result->Success();
          return;
        }
        result->NotImplemented();
      });

  flutter_controller_->engine()->SetNextFrameCallback([&]() {
    this->Show();
  });

  // Flutter can complete the first frame before the "show window" callback is
  // registered. The following call ensures a frame is pending to ensure the
  // window is shown. It is a no-op if the first frame hasn't completed yet.
  flutter_controller_->ForceRedraw();

  return true;
}

void FlutterWindow::OnDestroy() {
  window_channel_ = nullptr;
  if (flutter_controller_) {
    flutter_controller_ = nullptr;
  }

  Win32Window::OnDestroy();
}

LRESULT
FlutterWindow::MessageHandler(HWND hwnd, UINT const message,
                              WPARAM const wparam,
                              LPARAM const lparam) noexcept {
  // Give Flutter, including plugins, an opportunity to handle window messages.
  if (flutter_controller_) {
    std::optional<LRESULT> result =
        flutter_controller_->HandleTopLevelWindowProc(hwnd, message, wparam,
                                                      lparam);
    if (result) {
      return *result;
    }
  }

  switch (message) {
    case WM_FONTCHANGE:
      flutter_controller_->engine()->ReloadSystemFonts();
      break;
  }

  return Win32Window::MessageHandler(hwnd, message, wparam, lparam);
}
