export const DomainVirusTotal = ({ jsonData }) => {
    const reportInfoData = jsonData.data.attributes
    const reportInfoStats = jsonData.data.attributes.last_analysis_stats

    return (
        <>
            <h3 className="font-bold">Clasificación:</h3>
            <ul>
                <li>Malicioso: <span>{reportInfoStats.malicious}</span></li>
                <li>Sospechoso: <span>{reportInfoStats.suspicious}</span></li>
                <li>Sin detecciones: <span>{reportInfoStats.harmless}</span></li>
                <li>Sin información: <span>{reportInfoStats.undetected}</span></li>
            </ul>

            <h3 className="font-bold">Reputación:</h3>
            <p className="font-bold mt-5"><span className="font-normal">{reportInfoData.reputation && "N/A"}</span></p>

            <h3 className="font-bold">Categorias:</h3>
            <p className="font-bold mt-5"><span className="font-normal">{reportInfoData.categories && "N/A"}</span></p>
        </ >
    );
}