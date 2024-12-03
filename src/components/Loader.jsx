import style from "@/styles/loader.module.css"

export const Loader = () => {
    return (
        <section className={style.loaderContainer}>
            <span className={style.loader}></span>
        </section>
    )
}