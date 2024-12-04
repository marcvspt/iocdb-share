export const HashPolySwarm = ({ jsonData }) => {

    return (
        <aside className="mt-3 p-6 border border-accent-dark rounded-lg shadow-lg bg-accent-dark">
            <pre>
                {jsonData}
            </pre>
        </aside >
    );
}