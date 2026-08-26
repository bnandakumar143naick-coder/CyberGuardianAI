/* CyberGuardian AI - scan page logic */

(function () {
  const uploadZone = document.getElementById("upload-zone");
  const fileInput = document.getElementById("file-input");
  const previewWrap = document.getElementById("preview-wrap");
  const previewImg = document.getElementById("preview-img");
  const imageActions = document.getElementById("image-actions");
  const btnAnalyzeImage = document.getElementById("btn-analyze-image");
  const btnRetake = document.getElementById("btn-retake");
  const btnAnalyzeText = document.getElementById("btn-analyze-text");
  const btnAnalyzeUrl = document.getElementById("btn-analyze-url");

  let selectedFile = null;

  if (uploadZone) {
    uploadZone.addEventListener("click", () => fileInput.click());

    uploadZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      uploadZone.classList.add("dragover");
    });
    uploadZone.addEventListener("dragleave", () => uploadZone.classList.remove("dragover"));
    uploadZone.addEventListener("drop", (e) => {
      e.preventDefault();
      uploadZone.classList.remove("dragover");
      if (e.dataTransfer.files.length) handleFileSelect(e.dataTransfer.files[0]);
    });

    fileInput.addEventListener("change", () => {
      if (fileInput.files.length) handleFileSelect(fileInput.files[0]);
    });

    btnRetake.addEventListener("click", () => {
      selectedFile = null;
      fileInput.value = "";
      previewWrap.style.display = "none";
      imageActions.style.display = "none";
      uploadZone.style.display = "block";
      CG.clearError();
    });
  }

  function handleFileSelect(file) {
    CG.clearError();
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (!allowed.includes(file.type)) {
      CG.showError("Unsupported file type. Please upload a JPG, PNG, or WEBP image.");
      return;
    }
    if (file.size > 8 * 1024 * 1024) {
      CG.showError("File is too large. Please upload an image under 8 MB.");
      return;
    }

    selectedFile = file;
    const reader = new FileReader();
    reader.onload = (e) => {
      previewImg.src = e.target.result;
      previewWrap.style.display = "block";
      imageActions.style.display = "flex";
      uploadZone.style.display = "none";
    };
    reader.readAsDataURL(file);
  }

  if (btnAnalyzeImage) {
    btnAnalyzeImage.addEventListener("click", async () => {
      if (!selectedFile) {
        CG.showError("Please select an image first.");
        return;
      }
      CG.clearError();
      CG.setLoading(true);
      btnAnalyzeImage.disabled = true;

      try {
        const formData = new FormData();
        formData.append("image", selectedFile);
        const result = await CG.postForm("/api/analyze-image", formData);
        CG.goToResult(result);
      } catch (err) {
        CG.showError(err.message);
      } finally {
        CG.setLoading(false);
        btnAnalyzeImage.disabled = false;
      }
    });
  }

  if (btnAnalyzeText) {
    btnAnalyzeText.addEventListener("click", async () => {
      const text = document.getElementById("text-input").value.trim();
      if (!text) {
        CG.showError("Please paste some text to analyse.");
        return;
      }
      CG.clearError();
      CG.setLoading(true);
      btnAnalyzeText.disabled = true;

      try {
        const result = await CG.postJSON("/api/analyze-text", { text });
        CG.goToResult(result);
      } catch (err) {
        CG.showError(err.message);
      } finally {
        CG.setLoading(false);
        btnAnalyzeText.disabled = false;
      }
    });
  }

  if (btnAnalyzeUrl) {
    btnAnalyzeUrl.addEventListener("click", async () => {
      const url = document.getElementById("url-input").value.trim();
      if (!url) {
        CG.showError("Please enter a URL to check.");
        return;
      }
      CG.clearError();
      CG.setLoading(true);
      btnAnalyzeUrl.disabled = true;

      try {
        const result = await CG.postJSON("/api/analyze-url", { url });
        CG.goToResult(result);
      } catch (err) {
        CG.showError(err.message);
      } finally {
        CG.setLoading(false);
        btnAnalyzeUrl.disabled = false;
      }
    });
  }
})();
