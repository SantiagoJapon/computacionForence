# Monitor de Seguridad de Red - Documentación Completa

## Descripción

El **Monitor de Seguridad de Red** es una aplicación web desarrollada con Flask que permite analizar archivos de tráfico de red en formatos **CSV** o **PCAP** para detectar anomalías y posibles actividades maliciosas. Ofrece una interfaz sencilla para cargar archivos, procesarlos y visualizar los resultados mediante gráficos interactivos generados con Plotly. Es una herramienta útil para administradores de red y profesionales de seguridad que necesitan identificar comportamientos sospechosos en el tráfico de red de forma eficiente.

---

## Requisitos Previos

Antes de instalar y ejecutar la aplicación, asegúrate de contar con lo siguiente:

- **Python 3.7 o superior**: Descárgalo desde [python.org](https://www.python.org/downloads/).
- **pip**: Gestor de paquetes de Python, normalmente incluido con Python.
- **Git**: Necesario para clonar el repositorio. Descárgalo desde [git-scm.com](https://git-scm.com/downloads).

> **Nota:** Puedes verificar tu versión de Python ejecutando `python --version` o `python3 --version` en la terminal.

---

## Instalación

Sigue estos pasos para configurar el proyecto en tu máquina local:

### 1. Clonar el Repositorio

Clona el repositorio desde GitHub con el siguiente comando:

```bash
git clone https://github.com/tu-usuario/tu-repositorio.git
cd tu-repositorio
```
### 2. Crear un Entorno virtual (Recomendado)
Crea y activa un entorno virtual para mantener las dependencias aisladas, para esto puedes usar Anaconda.
O en el caso de que no lo tengas puedes usar:

```bash
python -m venv venv
```
-En Linux/Mac:
```bash
source venv/bin/activate
```
-En Windows:
```bash
venv\Scripts\activate
```
>**Tip:** Una vez activado, verás (venv) en tu terminal. Para salir del entorno, usa deactivate.
### 3. Instalar Dependencias
Instala las libreiras necesarias listadas en requirements.txt:
```bash
pip install -r requirements.txt
```
### 4. Ejecutar la Aplicacion
Inicia la plicacion con:
```bash
python app.py
```
>**Tip:** Recuerda estar dentro del directorio en el que esta el proyecto.
## Uso

La aplicación es fácil de usar. Sigue estos pasos:

### Cargar un Archivo
- Accede a `http://127.0.0.1:5000/`.
- Selecciona un archivo en formato CSV o PCAP y haz clic en "Analizar".

### Visualizar Resultados
- Si se detectan anomalías o actividades maliciosas, se mostrarán gráficos interactivos.
- Un mensaje indicará el estado del análisis (éxito o error).

## Estructura del Proyecto

El proyecto está organizado de la siguiente manera:

- **`app.py`**: Contiene la lógica principal de la aplicación Flask.
- **`templates/index.html`**: Plantilla HTML para la interfaz de usuario.
- **`static/styles.css`**: Archivo CSS para los estilos de la interfaz.
## Detalles del Codigo
importaciones Principales en app.py
```python
from flask import Flask, render_template, request, redirect, url_for, flash
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import pyshark
import os
import tempfile
import logging
```
## Detalles del Código

### Librerías Utilizadas

- **Flask**: Maneja las rutas y el renderizado de páginas web.
- **pandas y numpy**: Procesan y analizan datos de tráfico.
- **plotly**: Genera gráficos interactivos para visualizar resultados.
- **pyshark**: Lee y procesa archivos PCAP.
- **os, tempfile, logging**: Gestionan archivos temporales y registran eventos.

### Configuración Básica

- **Logging**: Configurado para registrar eventos y errores con detalles como nivel, fecha y mensaje:
  ```python
  logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
  ```
### Carpeta templates: Se crea automaticamente si no existe
```python
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
```
## Clase networkAnomalyAnalyzer
Esta clase encapsula la logica del analisis del trafico de red
- __init__(ruta_archivo): Inicializa la clase con la ruta del archivo y variables para datos, anomalías y maliciosos.
- cargar_datos(): Determina el tipo de archivo y lo carga:
```python
if self.ruta_archivo.lower().endswith('.pcap'):
    return self.cargar_datos_pcap()
elif self.ruta_archivo.lower().endswith('.csv'):
    return self.cargar_datos_csv()
```
- cargar_datos_csv(): Lee archivos CSV con pandas, convierte datos a numéricos y registra el resultado.
- cargar_datos_pcap(): Procesa archivos PCAP con pyshark, extrayendo información como IPs y puertos en bloques.
- detectar_anomalias(): Usa Z-scores, análisis temporal y reglas para identificar anomalías.
- filtrar_maliciosos(): Clasifica anomalías como maliciosas según criterios como puntuación alta.
- generar_grafico(): Crea gráficos interactivos con barras y líneas usando Plotly.
##Ruta principal
```python
@app.route('/', methods=['GET', 'POST'])
def index():
    # Maneja solicitudes GET y POST
```
- GET: Renderiza la página inicial con el formulario de carga.
- POST: Procesa el archivo subido, ejecuta el análisis y muestra los resultados.
## Solucion de Problemas
Aqui tienes soluciones a problemas comunes: 
- Error al cargar archivos PCAP: Asegúrate de que pyshark esté instalado (pip install pyshark) y que el archivo no esté corrupto.
- Los gráficos no se muestran: Verifica que plotly esté instalado y que los datos no estén vacíos.
- La aplicación no se inicia: Revisa las dependencias en requirements.txt y consulta los logs para identificar errores.
---
Esta documentación proporciona una guía completa para instalar, usar y contribuir al proyecto Monitor de Seguridad de Red. Está diseñada para ser útil tanto para usuarios nuevos como para desarrolladores experimentados.
