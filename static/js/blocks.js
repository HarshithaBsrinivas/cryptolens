"use strict";

/* Tab 3: the same picture through AES-ECB, AES-CBC and AES-GCM. */
(() => {
  const { h, api, showError, bytesToB64, b64ToBytes, number } = CL;
  const SIZE = 128;
  const form = document.getElementById("img-form");
  const errorEl = document.getElementById("img-error");
  const fileField = document.getElementById("img-file-field");
  const fileInput = document.getElementById("img-file");
  const notes = document.getElementById("img-notes");
  const canvases = { orig: "cv-orig", ecb: "cv-ecb", cbc: "cv-cbc", gcm: "cv-gcm" };
  let started = false;

  const ctxOf = (id) => document.getElementById(id).getContext("2d", { willReadFrequently: true });

  /* A picture made of flat shapes, so ECB's weakness is obvious. */
  function drawSample() {
    const c = ctxOf(canvases.orig);
    c.fillStyle = "#f5c542";
    c.fillRect(0, 0, SIZE, SIZE);
    c.fillStyle = "#11203b";
    c.fillRect(0, 88, SIZE, 40);
    c.fillStyle = "#d1432b";
    c.beginPath();
    c.arc(64, 54, 34, 0, Math.PI * 2);
    c.fill();
    c.fillStyle = "#f8fafb";
    c.beginPath();
    c.arc(64, 54, 18, 0, Math.PI * 2);
    c.fill();
    c.fillStyle = "#11203b";
    c.fillRect(56, 46, 16, 16);
    c.fillStyle = "#1f8a70";
    c.fillRect(0, 0, 24, 24);
    c.fillRect(104, 0, 24, 24);
  }

  function drawUpload(file) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const img = new Image();
      img.onload = () => {
        const c = ctxOf(canvases.orig);
        c.fillStyle = "#fff";
        c.fillRect(0, 0, SIZE, SIZE);
        const scale = Math.min(SIZE / img.width, SIZE / img.height);
        const w = img.width * scale, hgt = img.height * scale;
        c.drawImage(img, (SIZE - w) / 2, (SIZE - hgt) / 2, w, hgt);
        URL.revokeObjectURL(url);
        resolve();
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error("That file could not be read as an image. Try a PNG or JPG."));
      };
      img.src = url;
    });
  }

  /* RGBA canvas data to packed RGB bytes (the alpha channel is always 255 and would add a pattern). */
  function toRgb(imageData) {
    const rgb = new Uint8Array(SIZE * SIZE * 3);
    for (let i = 0, j = 0; i < imageData.data.length; i += 4) {
      rgb[j++] = imageData.data[i];
      rgb[j++] = imageData.data[i + 1];
      rgb[j++] = imageData.data[i + 2];
    }
    return rgb;
  }

  function paint(id, rgb) {
    const c = ctxOf(id);
    const image = c.createImageData(SIZE, SIZE);
    for (let i = 0, j = 0; i < rgb.length; i += 3, j += 4) {
      image.data[j] = rgb[i];
      image.data[j + 1] = rgb[i + 1];
      image.data[j + 2] = rgb[i + 2];
      image.data[j + 3] = 255;
    }
    c.putImageData(image, 0, 0);
  }

  const stat = (s) => `${number(s.unique_blocks)} of ${number(s.total_blocks)} blocks unique`;

  async function run() {
    showError(errorEl, "");
    const useUpload = form.elements.src.value === "upload";
    if (useUpload) {
      if (!fileInput.files[0]) {
        showError(errorEl, "Choose an image first, or switch back to the sample picture.");
        return;
      }
      await drawUpload(fileInput.files[0]);
    } else {
      drawSample();
    }
    const rgb = toRgb(ctxOf(canvases.orig).getImageData(0, 0, SIZE, SIZE));
    const res = await api("/api/image-modes", { pixels_b64: bytesToB64(rgb) });

    for (const mode of ["ecb", "cbc", "gcm"]) {
      paint(canvases[mode], b64ToBytes(res[mode].b64));
      document.getElementById(`st-${mode}`).textContent = stat(res[mode]);
    }
    document.getElementById("st-orig").textContent = stat(res.original);

    const repeated = res.ecb.total_blocks - res.ecb.unique_blocks;
    notes.replaceChildren(
      h("p", {},
        h("b", {}, "ECB "),
        repeated > 0
          ? `repeats ${number(repeated)} of ${number(res.ecb.total_blocks)} blocks. Equal pixels give equal ciphertext, so the outline of the picture shows through.`
          : "did not repeat any blocks for this picture because it has no repeated 16-byte areas. Try the sample picture."),
      h("p", {},
        h("b", {}, "CBC and GCM "),
        "mix in an IV or counter, so equal pixels encrypt differently and the result looks like random noise."),
      h("p", { class: "small" }, "The unique-block count measures this directly: each 16-byte block is compared with every other block.")
    );
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      await run();
    } catch (err) {
      showError(errorEl, err.message);
    } finally {
      button.disabled = false;
    }
  });

  form.addEventListener("change", (event) => {
    if (event.target.name === "src") fileField.hidden = form.elements.src.value !== "upload";
  });

  CL.start.blocks = () => {
    if (started) return;
    started = true;
    run().catch((err) => showError(errorEl, err.message));
  };
})();
