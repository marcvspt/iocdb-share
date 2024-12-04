export const DomainOTX = ({ jsonData }) => {
    const reportData = jsonData

    return (
        <aside className="mt-3 p-6 border border-accent-dark rounded-lg shadow-lg bg-accent-dark">
            <h3 className="font-bold">Reportes:</h3>
            <p>
                <span>{reportData.pulse_info.count}</span>
            </p>
        </aside>
    );
}