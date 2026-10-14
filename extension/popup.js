const lista = document.getElementById("lista");
const cuenta = document.getElementById("cuenta");
const error = document.getElementById("error");
const selector = document.getElementById("usuario");

function claseRiesgo(riesgo) {
  const valor = (riesgo || "").toLowerCase();
  if (valor === "alto") return "alto";
  if (valor === "medio") return "medio";
  return "bajo";
}

async function enviarFeedback(de, accion) {
  try {
    const email = selector.value;
    const res = await fetch("http://127.0.0.1:5000/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        usuario: email,
        de: de,
        accion: accion,
      }),
    });
    const data = await res.json();
    alert(data.mensaje || "Guardado");
    cargar();
  } catch (e) {
    alert("No se pudo guardar. Fijate que server.py este abierto.");
  }
}

function mostrar(data) {
  cuenta.textContent = data.cuenta || "Cuenta conectada";
  lista.innerHTML = "";

  if (!data.correos || data.correos.length === 0) {
    lista.innerHTML = "<p>No hay correos para mostrar.</p>";
    return;
  }

  data.correos.forEach((correo) => {
    const motivos = (correo.motivos || []).join(", ") || "sin motivos";
    const tarjeta = document.createElement("section");
    tarjeta.className = "tarjeta";
    tarjeta.innerHTML = `
      <p><span>De</span> ${correo.de || "(sin remitente)"}</p>
      <p><span>Asunto</span> ${correo.asunto || "(sin asunto)"}</p>
      <div class="riesgo ${claseRiesgo(correo.riesgo)}">
        ${correo.riesgo || "Bajo"} · ${correo.puntos ?? 0} puntos
      </div>
      <p class="motivos"><strong>Motivos:</strong> ${motivos}</p>
      <div class="botones">
        <button class="ok btn-confiar">Confiar</button>
        <button class="alerta btn-sospechoso">Sospechoso</button>
      </div>
    `;
    lista.appendChild(tarjeta);

    const de = correo.de || "";
    tarjeta.querySelector(".btn-confiar").addEventListener("click", () => {
      enviarFeedback(de, "confiar");
    });
    tarjeta.querySelector(".btn-sospechoso").addEventListener("click", () => {
      enviarFeedback(de, "sospechoso");
    });
  });
}

function llenarSelector(cuentas) {
  const actual = selector.value;
  selector.innerHTML = "";

  cuentas.forEach((email) => {
    const option = document.createElement("option");
    option.value = email;
    option.textContent = email;
    selector.appendChild(option);
  });

  if (actual && cuentas.includes(actual)) {
    selector.value = actual;
  }
}

async function cargar() {
  error.textContent = "";
  cuenta.textContent = "Cargando...";
  lista.innerHTML = "";

  try {
    const sesiones = await fetch("http://127.0.0.1:5000/sesiones").then((r) => r.json());
    const cuentas = sesiones.cuentas || [];

    if (cuentas.length === 0) {
      cuenta.textContent = "Sin sesion";
      error.textContent = "Entra primero a Iniciar sesion con otra cuenta.";
      return;
    }

    llenarSelector(cuentas);
    const email = selector.value;

    const res = await fetch(
      "http://127.0.0.1:5000/analizar_web?email=" + encodeURIComponent(email)
    );
    if (!res.ok) throw new Error("El servidor respondio mal");
    const data = await res.json();
    mostrar(data);
  } catch (e) {
    cuenta.textContent = "Sin conexion";
    error.textContent = "No se pudo hablar con Python. Fijate que server.py este abierto.";
  }
}

selector.addEventListener("change", cargar);
cargar();