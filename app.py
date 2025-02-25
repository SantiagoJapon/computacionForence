from flask import Flask, render_template, request, redirect, url_for, flash
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import pyshark
import os
import tempfile
import logging

# Configuración de logging más detallada
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = os.urandom(24)

if not os.path.exists('templates'):
    os.makedirs('templates')

class NetworkAnomalyAnalyzer:
    def __init__(self, ruta_archivo):
        self.ruta_archivo = ruta_archivo
        self.datos = None
        self.anomalias = None
        self.maliciosos = None

    def cargar_datos(self):
        if self.ruta_archivo.lower().endswith('.pcap'):
            return self.cargar_datos_pcap()
        elif self.ruta_archivo.lower().endswith('.csv'):
            return self.cargar_datos_csv()
        else:
            logging.error(f"Formato de archivo no soportado: {self.ruta_archivo}")
            return None

    def cargar_datos_csv(self):
        try:
            logging.info(f"Intentando cargar CSV desde: {self.ruta_archivo}")
            self.datos = pd.read_csv(self.ruta_archivo, encoding='utf-8', on_bad_lines='skip', dtype=str)
            self.datos = self.datos.apply(pd.to_numeric, errors='ignore')
            logging.info(f"Datos CSV cargados correctamente ({len(self.datos)} registros). Columnas: {list(self.datos.columns)}")
            return self.datos
        except Exception as e:
            logging.error(f"Error al cargar el archivo CSV: {str(e)}")
            return None

    def cargar_datos_pcap(self, chunk_size=1000):
        try:
            logging.info(f"Intentando cargar PCAP desde: {self.ruta_archivo}")
            registros = []
            cap = pyshark.FileCapture(self.ruta_archivo)
            logging.debug("Iniciando lectura de paquetes del archivo PCAP.")
            packet_count = 0
            
            for pkt in cap:
                try:
                    registro = {}
                    registro['timestamp'] = float(pkt.sniff_timestamp) if hasattr(pkt, 'sniff_timestamp') else None
                    registro['length'] = int(pkt.length) if hasattr(pkt, 'length') else None
                    registro['protocol'] = pkt.highest_layer if hasattr(pkt, 'highest_layer') else None
                    if hasattr(pkt, 'ip'):
                        registro['src_ip'] = pkt.ip.src if hasattr(pkt.ip, 'src') else None
                        registro['dst_ip'] = pkt.ip.dst if hasattr(pkt.ip, 'dst') else None
                        registro['ttl'] = int(pkt.ip.ttl) if hasattr(pkt.ip, 'ttl') else None
                    if hasattr(pkt, 'tcp'):
                        registro['src_port'] = int(pkt.tcp.srcport) if hasattr(pkt.tcp, 'srcport') else None
                        registro['dst_port'] = int(pkt.tcp.dstport) if hasattr(pkt.tcp, 'dstport') else None
                        registro['tcp_flags'] = pkt.tcp.flags if hasattr(pkt.tcp, 'flags') else None
                    elif hasattr(pkt, 'udp'):
                        registro['src_port'] = int(pkt.udp.srcport) if hasattr(pkt.udp, 'srcport') else None
                        registro['dst_port'] = int(pkt.udp.dstport) if hasattr(pkt.udp, 'dstport') else None
                    
                    registros.append(registro)
                    packet_count += 1
                    
                    if len(registros) >= chunk_size:
                        df_chunk = pd.DataFrame(registros)
                        self.datos = pd.concat([self.datos, df_chunk], ignore_index=True) if self.datos is not None else df_chunk
                        registros = []
                        logging.debug(f"Procesado chunk con {chunk_size} paquetes (total: {packet_count}).")
                except AttributeError as e:
                    logging.warning(f"Paquete incompleto en PCAP: {str(e)}")
                    continue
                except Exception as e:
                    logging.warning(f"Error al procesar paquete: {str(e)}")
                    continue
            
            if registros:
                df_chunk = pd.DataFrame(registros)
                self.datos = pd.concat([self.datos, df_chunk], ignore_index=True) if self.datos is not None else df_chunk
                logging.debug(f"Procesados {len(registros)} paquetes finales (total: {packet_count}).")
            
            cap.close()  # Cerrar explícitamente el archivo
            
            if self.datos is not None and not self.datos.empty:
                logging.info(f"Datos PCAP cargados correctamente ({len(self.datos)} paquetes). Columnas: {list(self.datos.columns)}")
                return self.datos
            else:
                logging.error("No se extrajeron datos válidos del archivo PCAP. Puede estar vacío o corrupto.")
                return None
        except Exception as e:
            logging.error(f"Error crítico al cargar el archivo PCAP: {str(e)}")
            return None

    def detectar_anomalias(self, z_score_threshold=3, ventana_temporal=600):
        if self.datos is None:
            logging.warning("No hay datos cargados para analizar.")
            return None

        datos_trabajo = self.datos.copy()
        puntuaciones_anomalia = pd.DataFrame(index=datos_trabajo.index)
        anomalias = datos_trabajo.copy()

        # 1. Análisis univariado para columnas numéricas
        columnas_numericas = datos_trabajo.select_dtypes(include=[np.number]).columns
        for col in columnas_numericas:
            valores = datos_trabajo[col].dropna()
            if len(valores) < 10 or valores.nunique() <= 2:
                continue
            median = valores.median()
            mad = np.median(np.abs(valores - median))
            if mad > 0:
                z_scores_mod = 0.6745 * (valores - median) / mad
                puntuaciones_anomalia[f'{col}_z'] = (np.abs(z_scores_mod) / z_score_threshold).clip(0, 1)
            logging.info(f"Análisis univariado en {col}: {len(valores)} valores, mediana={median}, MAD={mad}")

        # 2. Análisis temporal (si hay timestamp)
        if 'timestamp' in datos_trabajo.columns:
            datos_trabajo['timestamp'] = pd.to_datetime(datos_trabajo['timestamp'], unit='s', errors='coerce')
            datos_trabajo = datos_trabajo.sort_values('timestamp')
            ventanas = datos_trabajo.groupby(pd.Grouper(key='timestamp', freq=f'{ventana_temporal}s')).size()
            if len(ventanas) > 1:
                media = ventanas.mean()
                std = ventanas.std()
                scores = ventanas.apply(lambda x: min(1.0, max(0, (x - media) / (3 * std + 1))))
                puntuaciones_anomalia['temporal_burst'] = datos_trabajo['timestamp'].map(
                    lambda ts: scores.get(ts.floor(f'{ventana_temporal}s'), 0)
                )
                logging.info(f"Análisis temporal: {len(ventanas)} ventanas, media={media}, std={std}")

        # 3. Reglas específicas para tráfico sospechoso
        if 'src_ip' in datos_trabajo.columns:
            ip_counts = datos_trabajo['src_ip'].value_counts()
            max_count = ip_counts.max()
            if max_count > 1:
                puntuaciones_anomalia['ip_freq'] = datos_trabajo['src_ip'].map(lambda x: min(1.0, ip_counts[x] / (10 + 0.1 * max_count)))
                logging.info(f"Detección de IPs frecuentes: {len(ip_counts)} IPs únicas, max_count={max_count}")

        # 4. Puntuación final
        if not puntuaciones_anomalia.empty:
            pesos = {'temporal_burst': 0.3, 'ip_freq': 0.4}
            for col in [c for c in puntuaciones_anomalia.columns if c.endswith('_z')]:
                pesos[col] = 0.3 / max(1, len([c for c in puntuaciones_anomalia.columns if c.endswith('_z')]))
            suma_pesos = sum(pesos.get(col, 0) for col in puntuaciones_anomalia.columns)
            if suma_pesos > 0:
                pesos = {k: v/suma_pesos for k, v in pesos.items()}
            puntuacion_final = pd.Series(0, index=puntuaciones_anomalia.index)
            for col in puntuaciones_anomalia.columns:
                if col in pesos:
                    puntuacion_final += puntuaciones_anomalia[col].fillna(0) * pesos[col]
            anomalias['anomaly_score'] = puntuacion_final
            indices_anomalias = puntuacion_final[puntuacion_final > 0.3].index
            if not indices_anomalias.empty:
                anomalias = datos_trabajo.loc[indices_anomalias].copy()
                logging.info(f"Anomalías detectadas: {len(anomalias)} registros con puntuación > 0.3")
            else:
                anomalias = pd.DataFrame(columns=datos_trabajo.columns)
                anomalias['anomaly_score'] = pd.Series(dtype=float)
                logging.info("No se detectaron anomalías con puntuación > 0.3")
        else:
            anomalias = pd.DataFrame(columns=datos_trabajo.columns)
            anomalias['anomaly_score'] = pd.Series(dtype=float)
            logging.warning("No se generaron puntuaciones de anomalía.")

        self.anomalias = anomalias
        return self.anomalias

    def filtrar_maliciosos(self):
        if self.anomalias is not None and not self.anomalias.empty:
            if 'malicioso' in self.anomalias.columns:
                self.maliciosos = self.anomalias[self.anomalias['malicioso'] == 1]
            elif 'phishing' in self.anomalias.columns:
                self.maliciosos = self.anomalias[self.anomalias['phishing'] == 1]
            elif 'anomaly_score' in self.anomalias.columns:
                self.maliciosos = self.anomalias[self.anomalias['anomaly_score'] >= 0.8]
            else:
                self.maliciosos = pd.DataFrame(columns=self.anomalias.columns)
                logging.warning("No se encontraron columnas para filtrar maliciosos.")
            logging.info(f"Registros maliciosos filtrados: {len(self.maliciosos) if self.maliciosos is not None else 0}")
        else:
            self.maliciosos = pd.DataFrame(columns=self.datos.columns if self.datos is not None else [])
            logging.info("No hay anomalías para filtrar maliciosos.")
        return self.maliciosos

    def generar_grafico(self, datos, titulo):
        if datos is None or datos.empty:
            return None
        conteo = datos.count().sort_values(ascending=False)
        fig = go.Figure()
        fig.add_trace(go.Bar(x=conteo.index, y=conteo.values, name='Anomalías', marker_color='#FF4C4C', opacity=0.8))
        fig.add_trace(go.Scatter(x=conteo.index, y=conteo.rolling(2, min_periods=1).mean(), name='Tendencia', line=dict(color='#1F77B4', width=2), mode='lines+markers'))
        fig.update_layout(
            title=titulo,
            xaxis_title='Columnas',
            yaxis_title='Cantidad',
            template='plotly_white',
            hovermode='x unified',
            height=600,
            updatemenus=[dict(type="buttons", buttons=[dict(label="Play", method="animate", args=[None, {"frame": {"duration": 500, "redraw": True}, "fromcurrent": True}])])]
        )
        frames = [go.Frame(data=[go.Bar(x=conteo.index, y=conteo.values * (i / 10))]) for i in range(10)]
        fig.frames = frames
        return fig.to_html(full_html=False)

@app.route('/', methods=['GET', 'POST'])
def index():
    contenido = {'maliciosos_html': None, 'generales_html': None, 'mensaje': None}
    
    if request.method == 'POST':
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No se seleccionó ningún archivo')
            return redirect(request.url)
        
        file = request.files['file']
        original_filename = file.filename
        _, file_extension = os.path.splitext(original_filename)
        tmp_file_path = None
        
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_extension) as tmp:
                tmp_file_path = tmp.name
                logging.info(f"Guardando archivo temporal en: {tmp_file_path}")
                file.save(tmp_file_path)
                
                analizador = NetworkAnomalyAnalyzer(tmp_file_path)
                datos = analizador.cargar_datos()
                if datos is not None:
                    analizador.detectar_anomalias()
                    analizador.filtrar_maliciosos()
                    if analizador.maliciosos is not None and not analizador.maliciosos.empty:
                        contenido['maliciosos_html'] = analizador.generar_grafico(analizador.maliciosos, '🔥 Actividad Maliciosa Detectada')
                    if analizador.anomalias is not None and not analizador.anomalias.empty:
                        contenido['generales_html'] = analizador.generar_grafico(analizador.anomalias, '⚠️ Anomalías Generales Detectadas')
                    if not contenido['maliciosos_html'] and not contenido['generales_html']:
                        contenido['mensaje'] = "✅ No se detectaron anomalías significativas en los datos"
                    else:
                        contenido['mensaje'] = "✅ Análisis completado"
                else:
                    contenido['mensaje'] = "❌ Error al cargar el archivo. Revisa el log para más detalles."
        finally:
            if tmp_file_path and os.path.exists(tmp_file_path):
                try:
                    os.unlink(tmp_file_path)
                    logging.info(f"Archivo temporal {tmp_file_path} eliminado correctamente.")
                except PermissionError as e:
                    logging.warning(f"No se pudo eliminar el archivo temporal {tmp_file_path}: {e}")
        
        return render_template('index.html', **contenido)
    
    return render_template('index.html', **contenido)

if __name__ == '__main__':
    app.run(debug=True)