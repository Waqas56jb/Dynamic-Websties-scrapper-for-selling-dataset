function toggleDropdown() {
    const dropdown = document.getElementById('dropdown-content');
    dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
}

function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const main = document.querySelector('.main');
    if (sidebar.style.left === '0px') {
        sidebar.style.left = '-250px';
        main.style.marginLeft = '0';
    } else {
        sidebar.style.left = '0';
        main.style.marginLeft = '250px';
    }
}
// Select All Rows
const selectAllButton = document.getElementById("select-all-button");

selectAllButton.addEventListener("click", () => {
    const rows = document.querySelectorAll("#data-table tbody tr");
    rows.forEach((row) => {
        row.querySelector(".row-checkbox").checked = true;
    });
});
// Undo Feature
const undoButton = document.getElementById("undo-button");

undoButton.addEventListener("click", () => {
    const rows = document.querySelectorAll("#data-table tbody tr");
    rows.forEach((row) => {
        row.querySelector(".row-checkbox").checked = false;
    });
});
// Send Emails
const sendEmailsButton = document.getElementById("send-emails-button");
const emailRecipients = document.getElementById("email-recipients");

sendEmailsButton.addEventListener("click", () => {
    const emails = [
        ...new Set(
            Array.from(document.querySelectorAll("#data-table tbody tr"))
                .map((row) => row.querySelector("td:nth-child(3)").textContent.trim())
                .filter((email) => email)
        ),
    ];
    emailRecipients.value = emails.join(", ");
    emailModal.style.display = "flex";
});
// Download Filtered CSV
const downloadButton = document.getElementById("download-button");

downloadButton.addEventListener("click", async () => {
    const selectedRows = document.querySelectorAll(".row-checkbox:checked");
    const selectedData = Array.from(selectedRows).map((row) => {
        const rowData = {};
        row.closest("tr").querySelectorAll("td").forEach((cell, index) => {
            const header = document.querySelector(`#data-table th:nth-child(${index + 1})`).textContent.trim();
            rowData[header] = cell.textContent.trim();
        });
        return rowData;
    });

    const response = await fetch("/download_filtered", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ data: selectedData }),
    });

    if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "filtered_data.csv";
        a.click();
    }
});