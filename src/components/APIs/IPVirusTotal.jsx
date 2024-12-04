export const IPVirusTotal = ({ jsonData }) => {
    const importanData = jsonData.data.attributes
    const reportData = jsonData.data.attributes.last_analysis_stats

    return (
        <aside className="mt-3 p-6 border border-accent-dark rounded-lg shadow-lg bg-accent-dark">
            <h3 className="font-bold">Empresas de ciberseguridad:</h3>
            <ul>
                <li>Malicioso: <span>{reportData.malicious}</span></li>
                <li>Sospechoso: <span>{reportData.suspicious}</span></li>
                <li>Sin detecciones: <span>{reportData.harmless}</span></li>
                <li>Sin información: <span>{reportData.undetected}</span></li>
            </ul>
            <p className="font-bold mt-5">Reputación de la comunidad: <span className="font-normal">{importanData.reputation}</span>
            </p>
        </aside >
    );
}