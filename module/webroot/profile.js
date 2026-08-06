(function (global) {
  "use strict";

  function read(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () {
        if (typeof reader.result === "string") resolve(reader.result);
        else reject(new Error("Profile file was unreadable"));
      };
      reader.onerror = function () { reject(new Error("Profile file was unreadable")); };
      reader.readAsText(file);
    });
  }

  function observe(input, report) {
    input.addEventListener("change", function () {
      var file = input.files !== null ? input.files[0] : undefined;
      if (file === undefined) {
        report({ ready: false, role: "", message: "" });
        return;
      }
      void read(file).then(function (text) {
        var role = global.RkaModel.parseProfile(text);
        report({ ready: true, role: role, message: "Profile loaded, not applied" });
      }, function (error) {
        report({
          ready: false,
          role: "",
          message: error instanceof Error ? error.message : "Profile file was invalid"
        });
      });
    });
  }

  global.RkaProfile = Object.freeze({ observe: observe });
})(globalThis);
