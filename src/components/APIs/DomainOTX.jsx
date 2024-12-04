export const DomainOTX = ({ jsonData }) => {
    const reportData = jsonData
    const reportsCount = reportData.pulse_info.count
    const reportInfo = reportData.pulse_info
    const reportInfoData = reportInfo.pulses

    console.log(reportInfoData)
    let results;
    if (reportsCount > 0 && reportInfo && reportInfoData) {
        console.log("If")
        results = reportInfoData.map(pulse => ({
            description: pulse.description,
            author: pulse.author.username,
            malwareFamilies: pulse.malware_families
        }));
    }

    return (
        <>
            <h3 className="font-bold">Reportes:</h3>
            {results && results.length > 0 ? (
                <ul>
                    {results.map((result, index) => (
                        <li key={index}>
                            <p>Descripción: <span className="font-normal">{result.description || "N/A"}</span></p>
                            <p className="font-bold mt-5">Autor: <span className="font-normal">{result.author || "N/A"}</span></p>
                            <p>Familias de Malware: <span className="font-normal">{result.malwareFamilies.length > 0 ? result.malwareFamilies.join(", ") : "Ninguna"}</span></p>
                        </li>
                    ))}
                </ul>
            ) : (
                <p>No hay reportes de este dominio.</p>
            )}
        </>
    );
}