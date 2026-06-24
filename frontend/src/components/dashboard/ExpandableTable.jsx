import { useState } from "react";

export default function ExpandableTable({ columns, rows, renderDetails }) {
  const [openIndex, setOpenIndex] = useState(null);

  return (
    <table>
      <thead>
        <tr>
          <th></th>
          {columns.map((col) => (
            <th key={col.key}>{col.label}</th>
          ))}
        </tr>
      </thead>

      <tbody>
        {rows.length === 0 ? (
          <tr>
            <td colSpan={columns.length + 1}>No data available</td>
          </tr>
        ) : (
          rows.map((row, index) => (
            <>
              <tr
                key={`row-${index}`}
                onClick={() =>
                  setOpenIndex(openIndex === index ? null : index)
                }
                style={{ cursor: "pointer" }}
              >
                <td>{openIndex === index ? "▾" : "▸"}</td>

                {columns.map((col) => (
                  <td key={col.key}>
                    {col.render
                      ? col.render(row[col.key], row)
                      : row[col.key] || "N/A"}
                  </td>
                ))}
              </tr>

              {openIndex === index && (
                <tr key={`details-${index}`}>
                  <td colSpan={columns.length + 1}>
                    <div className="expand-details">
                      {renderDetails ? (
                        renderDetails(row)
                      ) : (
                        <pre>{JSON.stringify(row, null, 2)}</pre>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </>
          ))
        )}
      </tbody>
    </table>
  );
}
